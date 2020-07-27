#include "py/objint.h"
#include "py/objstr.h"

#include "beam/beam.h"
#include "beam/functions.h"
#include "beam/misc.h"
#include "hw_crypto/keykeeper.h"

/// package: trezorcrypto.beam

//
#define DBG_PRINT(msg, arr, len)     \
  printf(msg);                       \
  for (size_t i = 0; i < len; i++) { \
    printf("%02x", ((int*)arr)[i]);  \
  }                                  \
  printf("\n");

// To get_uint64_t and other helper functions
// TAKEN FROM: #include "modtrezorcrypto-monero.h"
static uint64_t mp_obj_uint64_get_checked_beam(mp_const_obj_t self_in) {
#if MICROPY_LONGINT_IMPL != MICROPY_LONGINT_IMPL_MPZ
#error "MPZ supported only"
#endif

  if (MP_OBJ_IS_SMALL_INT(self_in)) {
    return MP_OBJ_SMALL_INT_VALUE(self_in);
  } else {
    byte buff[8];
    uint64_t res = 0;
    mp_obj_t* o = MP_OBJ_TO_PTR(self_in);

    mp_obj_int_to_bytes_impl(o, true, 8, buff);
    for (int i = 0; i < 8; i++) {
      res <<= i > 0 ? 8 : 0;
      res |= (uint64_t)(buff[i] & 0xff);
    }
    return res;
  }
}

static uint64_t mp_obj_get_uint64_beam(mp_const_obj_t arg) {
  if (arg == mp_const_false) {
    return 0;
  } else if (arg == mp_const_true) {
    return 1;
  } else if (MP_OBJ_IS_SMALL_INT(arg)) {
    return MP_OBJ_SMALL_INT_VALUE(arg);
  } else if (MP_OBJ_IS_TYPE(arg, &mp_type_int)) {
    return mp_obj_uint64_get_checked_beam(arg);
  } else {
    if (MICROPY_ERROR_REPORTING == MICROPY_ERROR_REPORTING_TERSE) {
      mp_raise_TypeError("can't convert to int");
    } else {
      nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError,
                                              "can't convert %s to int",
                                              mp_obj_get_type_str(arg)));
    }
  }
}

//
// New Transaction Manager
//

// Used for getters
enum TRANSACTION_MANAGER_POINT_TYPES {
  TX_COMMON_KERNEL_COMMITMENT = 0,
  TX_COMMON_KERNEL_SIGNATURE_NONCEPUB,
  TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_NONCEPUB
};
enum TRANSACTION_MANAGER_SCALAR_TYPE {
  TX_COMMON_KERNEL_SIGNATURE_K,
  TX_COMMON_OFFSET_SK,
  TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_K,
  TX_SEND_USER_AGREEMENT,
  TX_STATE_KERNEL_MSG // temporary state msg
};

typedef struct _mp_obj_coin_id_t {
  mp_obj_base_t base;
  BeamCrypto_CoinID cid;
} mp_obj_coin_id_t;
STATIC const mp_obj_type_t mod_trezorcrypto_beam_coin_id_type;

typedef struct {
  TxAggr tx_aggr;
  BeamCrypto_UintBig kernel_msg;
  BeamCrypto_UintBig wallet_id_msg;
  secp256k1_scalar sk_krn;
  secp256k1_scalar sk_nonce;
} _beam_transaction_manager_state;

void _beam_transaction_manager_clear_state(_beam_transaction_manager_state* state) {
  state->tx_aggr.m_Ins.m_Beams = 0;
  state->tx_aggr.m_Ins.m_Assets = 0;
  state->tx_aggr.m_Outs.m_Beams = 0;
  state->tx_aggr.m_Outs.m_Assets = 0;
  state->tx_aggr.m_AssetID = 0;
  secp256k1_scalar_clear(&state->tx_aggr.m_sk);

  memzero(state->kernel_msg.m_pVal, DIGEST_LENGTH);
  memzero(state->wallet_id_msg.m_pVal, DIGEST_LENGTH);
  secp256k1_scalar_clear(&state->sk_krn);
  secp256k1_scalar_clear(&state->sk_nonce);
}

typedef struct _mp_obj_beam_transaction_manager_t {
  mp_obj_base_t base;
  // Add CoinIDs to these vecs first, then set appropriate data in TxCommon part
  cid_vec_t inputs;
  cid_vec_t outputs;

  BeamCrypto_KeyKeeper key_keeper;

  BeamCrypto_TxCommon tx_common;
  BeamCrypto_TxMutualInfo tx_mutual_info;
  BeamCrypto_TxSenderParams tx_sender_params;

  _beam_transaction_manager_state tx_state;
} mp_obj_beam_transaction_manager_t;
STATIC const mp_obj_type_t mod_trezorcrypto_beam_transaction_manager_type;

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_make_new(
    const mp_obj_type_t* type, size_t n_args, size_t n_kw,
    const mp_obj_t* args) {
  mp_arg_check_num(n_args, n_kw, 0, 0, false);
  mp_obj_beam_transaction_manager_t* o =
      m_new_obj(mp_obj_beam_transaction_manager_t);
  o->base.type = type;

  vec_init(&o->inputs);
  vec_init(&o->outputs);

  // Set invalid nonce slot at initialization, so transaction sign won't occur
  o->tx_sender_params.m_iSlot = MAX_NONCE_SLOT + 1;

  _beam_transaction_manager_clear_state(&o->tx_state);

  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager___del__(mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  // TODO: if we add support for nested kernels, we should also deinit all
  // nested inputs/outputs list of these kernels
  // @see beam/misc.c in `transaction_free()` method
  // vec_deinit_inner_ptrs(&o->inputs, tx_input_t);
  // transaction_free_outputs(&o->outputs);

  vec_deinit(&o->inputs);
  vec_deinit(&o->outputs);

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager___del___obj,
    mod_trezorcrypto_beam_transaction_manager___del__);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_clear_state(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);
  _beam_transaction_manager_clear_state(&o->tx_state);

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_clear_state_obj,
    mod_trezorcrypto_beam_transaction_manager_clear_state);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_add_input(
    mp_obj_t self, const mp_obj_t cid_input) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);
  mp_obj_coin_id_t* input_obj = MP_OBJ_TO_PTR(cid_input);
  BeamCrypto_CoinID cid;
  memcpy(&cid, &input_obj->cid, sizeof(BeamCrypto_CoinID));

  vec_push(&o->inputs, cid);

  // Move data and its length to TxCommon part
  o->tx_common.m_pIns = o->inputs.data;
  o->tx_common.m_Ins = o->inputs.length;

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezorcrypto_beam_transaction_manager_add_input_obj,
    mod_trezorcrypto_beam_transaction_manager_add_input);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_add_output(
    mp_obj_t self, const mp_obj_t cid_output) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);
  mp_obj_coin_id_t* output_obj = MP_OBJ_TO_PTR(cid_output);
  BeamCrypto_CoinID cid;
  memcpy(&cid, &output_obj->cid, sizeof(BeamCrypto_CoinID));

  vec_push(&o->outputs, cid);

  // Move data and its length to TxCommon part
  o->tx_common.m_pOuts = o->outputs.data;
  o->tx_common.m_Outs = o->outputs.length;

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezorcrypto_beam_transaction_manager_add_output_obj,
    mod_trezorcrypto_beam_transaction_manager_add_output);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_init_keykeeper(
    mp_obj_t self, const mp_obj_t seed_arg) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  mp_buffer_info_t seed;
  mp_get_buffer_raise(seed_arg, &seed, MP_BUFFER_READ);

  BeamCrypto_UintBig seed_beam;
  memcpy(seed_beam.m_pVal, (const uint8_t*)seed.buf, DIGEST_LENGTH);

  BeamCrypto_Kdf_Init(&o->key_keeper.m_MasterKey, &seed_beam);

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezorcrypto_beam_transaction_manager_init_keykeeper_obj,
    mod_trezorcrypto_beam_transaction_manager_init_keykeeper);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_set_common_info(
    size_t n_args, const mp_obj_t* args) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(args[0]);
  // Attention! Inputs and outputs should be added beforehand using add_input(), add_output() methods

  // Get Kernel
  {
    const uint64_t fee = mp_obj_get_uint64_beam(args[1]);
    const uint64_t min_height = mp_obj_get_uint64_beam(args[2]);
    const uint64_t max_height = mp_obj_get_uint64_beam(args[3]);

    o->tx_common.m_Krn.m_Fee = fee;
    o->tx_common.m_Krn.m_hMin = min_height;
    o->tx_common.m_Krn.m_hMax = max_height;

    mp_buffer_info_t peer_commitment_x;
    mp_get_buffer_raise(args[4], &peer_commitment_x, MP_BUFFER_READ);
    const uint8_t peer_commitment_y = mp_obj_get_int(args[5]);
    memcpy(&o->tx_common.m_Krn.m_Commitment.m_X, (const uint8_t*)peer_commitment_x.buf,
           DIGEST_LENGTH);
    o->tx_common.m_Krn.m_Commitment.m_Y = peer_commitment_y;

    // Get signature
    {
      // Get nonce_pub
      // x part
      mp_buffer_info_t nonce_pub_x;
      mp_get_buffer_raise(args[6], &nonce_pub_x, MP_BUFFER_READ);
      // y part
      const uint8_t nonce_pub_y = mp_obj_get_int(args[7]);
      // Convert nonce pub from two parts to CompactPoint
      memcpy(o->tx_common.m_Krn.m_Signature.m_NoncePub.m_X.m_pVal, (const uint8_t*)nonce_pub_x.buf, DIGEST_LENGTH);
      o->tx_common.m_Krn.m_Signature.m_NoncePub.m_Y = nonce_pub_y;

      // Get scalar K
      mp_buffer_info_t signature_scalar_k;
      mp_get_buffer_raise(args[8], &signature_scalar_k, MP_BUFFER_READ);
      memcpy(o->tx_common.m_Krn.m_Signature.m_k.m_pVal, (const uint8_t*)signature_scalar_k.buf, DIGEST_LENGTH);
    }
  }

  mp_buffer_info_t offset;
  mp_get_buffer_raise(args[9], &offset, MP_BUFFER_READ);
  memcpy(o->tx_common.m_kOffset.m_pVal, (const uint8_t*)offset.buf, DIGEST_LENGTH);

  // Parameters accepted
  return mp_obj_new_int(1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_transaction_manager_set_common_info_obj, 10, 10,
    mod_trezorcrypto_beam_transaction_manager_set_common_info);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_set_mutual_info(
    size_t n_args, const mp_obj_t* args) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(args[0]);

  mp_buffer_info_t peer_id;
  mp_get_buffer_raise(args[1], &peer_id, MP_BUFFER_READ);
  memcpy(o->tx_mutual_info.m_Peer.m_pVal, (const uint8_t*)peer_id.buf, DIGEST_LENGTH);

  o->tx_mutual_info.m_MyIDKey = mp_obj_get_uint64_beam(args[2]);

  // Get PaymentProofSignature
  {
    // Get nonce_pub
    // x part
    mp_buffer_info_t nonce_pub_x;
    mp_get_buffer_raise(args[3], &nonce_pub_x, MP_BUFFER_READ);
    // y part
    const uint8_t nonce_pub_y = mp_obj_get_int(args[4]);
    // Convert nonce pub from two parts to CompactPoint
    memcpy(o->tx_mutual_info.m_PaymentProofSignature.m_NoncePub.m_X.m_pVal, (const uint8_t*)nonce_pub_x.buf, DIGEST_LENGTH);
    o->tx_mutual_info.m_PaymentProofSignature.m_NoncePub.m_Y = nonce_pub_y;

    // Get scalar K
    mp_buffer_info_t signature_scalar_k;
    mp_get_buffer_raise(args[5], &signature_scalar_k, MP_BUFFER_READ);
    memcpy(o->tx_mutual_info.m_PaymentProofSignature.m_k.m_pVal, (const uint8_t*)signature_scalar_k.buf, DIGEST_LENGTH);
  }

  // Parameters accepted
  return mp_obj_new_int(1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_transaction_manager_set_mutual_info_obj, 6, 6,
    mod_trezorcrypto_beam_transaction_manager_set_mutual_info);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_set_sender_params(
    size_t n_args, const mp_obj_t* args) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(args[0]);

  const uint32_t nonce_slot = mp_obj_get_int(args[1]);
  if (!is_valid_nonce_slot(nonce_slot))
      return mp_obj_new_int(0);

  o->tx_sender_params.m_iSlot = nonce_slot;

  mp_buffer_info_t user_agreement;
  mp_get_buffer_raise(args[2], &user_agreement, MP_BUFFER_READ);

  memcpy(o->tx_sender_params.m_UserAgreement.m_pVal, (const uint8_t*)user_agreement.buf, DIGEST_LENGTH);

  // Parameters accepted
  return mp_obj_new_int(1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_transaction_manager_set_sender_params_obj, 3, 3,
    mod_trezorcrypto_beam_transaction_manager_set_sender_params);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_1(
    mp_obj_t self, const mp_obj_t send_phase_arg) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  const uint32_t send_phase = mp_obj_get_int(send_phase_arg);
  // TODO
  UNUSED(send_phase);

  const int res = BeamCrypto_KeyKeeper_SignTx_Send_Part_1(&o->key_keeper,
                                                          &o->tx_common,
                                                          &o->tx_mutual_info,
                                                          &o->tx_sender_params,
                                                          &o->tx_state.tx_aggr);
  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_1_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_1);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_2(
    mp_obj_t self, const mp_obj_t arg_nonce_from_slot) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  mp_buffer_info_t nonce_from_slot;
  mp_get_buffer_raise(arg_nonce_from_slot, &nonce_from_slot, MP_BUFFER_READ);

  const int res = BeamCrypto_KeyKeeper_SignTx_Send_Part_2(&o->key_keeper,
                                                          &o->tx_common,
                                                          &o->tx_mutual_info,
                                                          &o->tx_state.tx_aggr,
                                                          (const uint8_t*)nonce_from_slot.buf,
                                                          &o->tx_state.wallet_id_msg,
                                                          &o->tx_state.kernel_msg,
                                                          &o->tx_state.sk_krn,
                                                          &o->tx_state.sk_nonce);
  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_2_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_2);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_3(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  const int res = BeamCrypto_KeyKeeper_SignTx_Send_Part_3(&o->tx_state.tx_aggr,
                                                          &o->tx_common,
                                                          &o->tx_mutual_info,
                                                          &o->tx_sender_params,
                                                          &o->tx_state.wallet_id_msg,
                                                          &o->tx_state.kernel_msg,
                                                          &o->tx_state.sk_krn,
                                                          &o->tx_state.sk_nonce);
  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_3_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_3);


STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_4(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  const int res = BeamCrypto_KeyKeeper_SignTx_Send_Part_4(&o->tx_state.tx_aggr,
                                                          &o->tx_common,
                                                          &o->tx_state.kernel_msg,
                                                          &o->tx_state.sk_krn,
                                                          &o->tx_state.sk_nonce);
  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_4_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_4);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_receive(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  const int res = BeamCrypto_KeyKeeper_SignTx_Receive(&o->key_keeper,
                                                      &o->tx_state.tx_aggr,
                                                      &o->tx_common,
                                                      &o->tx_mutual_info);
  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_receive_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_receive);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_1(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  const int res = BeamCrypto_KeyKeeper_SignTx_Split_Part_1(&o->key_keeper,
                                                           &o->tx_common,
                                                           &o->tx_state.tx_aggr,
                                                           &o->tx_state.kernel_msg,
                                                           &o->tx_state.sk_krn,
                                                           &o->tx_state.sk_nonce);

  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_1_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_1);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_2(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  const int res = BeamCrypto_KeyKeeper_SignTx_Split_Part_2(&o->tx_common,
                                                           &o->tx_state.tx_aggr,
                                                           &o->tx_state.kernel_msg,
                                                           &o->tx_state.sk_krn,
                                                           &o->tx_state.sk_nonce);

  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_2_obj,
    mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_2);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_get_tx_aggr_coins_info(
    mp_obj_t self) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(self);

  mp_obj_t tuple[5] = {
    mp_obj_new_int_from_ull(o->tx_state.tx_aggr.m_Ins.m_Beams),
    mp_obj_new_int_from_ull(o->tx_state.tx_aggr.m_Ins.m_Assets),
    mp_obj_new_int_from_ull(o->tx_state.tx_aggr.m_Outs.m_Beams),
    mp_obj_new_int_from_ull(o->tx_state.tx_aggr.m_Outs.m_Assets),
    mp_obj_new_int(o->tx_state.tx_aggr.m_AssetID),
  };
  return mp_obj_new_tuple(5, tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_beam_transaction_manager_get_tx_aggr_coins_info_obj,
    mod_trezorcrypto_beam_transaction_manager_get_tx_aggr_coins_info);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_get_point(
    size_t n_args, const mp_obj_t* args) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(args[0]);

  const uint32_t point_type = mp_obj_get_int(args[1]);

  mp_buffer_info_t point_x;
  mp_get_buffer_raise(args[2], &point_x, MP_BUFFER_RW);
  mp_buffer_info_t point_y;
  mp_get_buffer_raise(args[3], &point_y, MP_BUFFER_RW);

  uint32_t res = BeamCrypto_KeyKeeper_Status_Ok;
  switch (point_type) {
    case TX_COMMON_KERNEL_COMMITMENT:
      memcpy((uint8_t*)point_x.buf, o->tx_common.m_Krn.m_Commitment.m_X.m_pVal, DIGEST_LENGTH);
      memcpy((uint8_t*)point_y.buf, &o->tx_common.m_Krn.m_Commitment.m_Y, sizeof(uint8_t));
      break;

    case TX_COMMON_KERNEL_SIGNATURE_NONCEPUB:
      memcpy((uint8_t*)point_x.buf, o->tx_common.m_Krn.m_Signature.m_NoncePub.m_X.m_pVal, DIGEST_LENGTH);
      memcpy((uint8_t*)point_y.buf, &o->tx_common.m_Krn.m_Signature.m_NoncePub.m_Y, sizeof(uint8_t));
      break;

    case TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_NONCEPUB:
      memcpy((uint8_t*)point_x.buf, o->tx_mutual_info.m_PaymentProofSignature.m_NoncePub.m_X.m_pVal, DIGEST_LENGTH);
      memcpy((uint8_t*)point_y.buf, &o->tx_mutual_info.m_PaymentProofSignature.m_NoncePub.m_Y, sizeof(uint8_t));
      break;

    default:
      res = BeamCrypto_KeyKeeper_Status_NotImpl;
      break;
  }

  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_transaction_manager_get_point_obj, 4, 4,
    mod_trezorcrypto_beam_transaction_manager_get_point);

STATIC mp_obj_t mod_trezorcrypto_beam_transaction_manager_get_scalar(
    size_t n_args, const mp_obj_t* args) {
  mp_obj_beam_transaction_manager_t* o = MP_OBJ_TO_PTR(args[0]);

  const uint32_t scalar_type = mp_obj_get_int(args[1]);

  mp_buffer_info_t scalar_data;
  mp_get_buffer_raise(args[2], &scalar_data, MP_BUFFER_RW);

  uint32_t res = BeamCrypto_KeyKeeper_Status_Ok;
  switch (scalar_type) {
    case TX_COMMON_OFFSET_SK:
      memcpy((uint8_t*)scalar_data.buf, o->tx_common.m_kOffset.m_pVal, DIGEST_LENGTH);
      break;

    case TX_COMMON_KERNEL_SIGNATURE_K:
      memcpy((uint8_t*)scalar_data.buf, o->tx_common.m_Krn.m_Signature.m_k.m_pVal, DIGEST_LENGTH);
      break;

    case TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_K:
      memcpy((uint8_t*)scalar_data.buf, o->tx_mutual_info.m_PaymentProofSignature.m_k.m_pVal, DIGEST_LENGTH);
      break;

    case TX_SEND_USER_AGREEMENT:
      memcpy((uint8_t*)scalar_data.buf, o->tx_sender_params.m_UserAgreement.m_pVal, DIGEST_LENGTH);
      break;

    case TX_STATE_KERNEL_MSG:
      memcpy((uint8_t*)scalar_data.buf, o->tx_state.kernel_msg.m_pVal, DIGEST_LENGTH);
      break;

    default:
      res = BeamCrypto_KeyKeeper_Status_NotImpl;
      break;
  }

  return mp_obj_new_int(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_transaction_manager_get_scalar_obj, 3, 3,
    mod_trezorcrypto_beam_transaction_manager_get_scalar);

STATIC mp_obj_t mod_trezorcrypto_beam_coin_id_make_new(
    const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* args) {
  mp_arg_check_num(n_args, n_kw, 0, 0, false);
  mp_obj_coin_id_t* o = m_new_obj(mp_obj_coin_id_t);
  o->base.type = type;

  coin_id_init(&o->cid);

  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_beam_coin_id_set(size_t n_args, const mp_obj_t* args) {
  mp_obj_coin_id_t* o = MP_OBJ_TO_PTR(args[0]);

  const uint64_t idx = mp_obj_get_uint64_beam(args[1]);
  const uint32_t type = (uint32_t)mp_obj_get_uint64_beam(args[2]);
  const uint32_t sub_idx = (uint32_t)mp_obj_get_uint64_beam(args[3]);
  const uint64_t amount = mp_obj_get_uint64_beam(args[4]);
  const uint32_t asset_id = (uint32_t)mp_obj_get_uint64_beam(args[5]);

  o->cid.m_Idx = idx;
  o->cid.m_Type = type;
  o->cid.m_SubIdx = sub_idx;
  o->cid.m_Amount = amount;
  o->cid.m_AssetID = asset_id;

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_coin_id_set_obj, 6, 6,
    mod_trezorcrypto_beam_coin_id_set);

STATIC mp_obj_t mod_trezorcrypto_beam_coin_id___del__(mp_obj_t self) {
  mp_obj_coin_id_t* o = MP_OBJ_TO_PTR(self);
  memzero(&(o->cid), sizeof(BeamCrypto_CoinID));
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_beam_coin_id___del___obj,
                                 mod_trezorcrypto_beam_coin_id___del__);


/// def from_mnemonic_beam(mnemonic: str) -> bytes:
///     '''
///     Generate BEAM seed from mnemonic and passphrase.
///     '''
STATIC mp_obj_t
mod_trezorcrypto_beam_from_mnemonic_beam(const mp_obj_t mnemonic) {
  mp_buffer_info_t mnemo;

  mp_get_buffer_raise(mnemonic, &mnemo, MP_BUFFER_READ);
  uint8_t seed[32];
  const char* pmnemonic = mnemo.len > 0 ? mnemo.buf : "";
  uint32_t mnemonic_size = mnemo.len;
  phrase_to_seed(pmnemonic, mnemonic_size, seed);

  return mp_obj_new_bytes(seed, sizeof(seed));
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_beam_from_mnemonic_beam_obj,
                                 mod_trezorcrypto_beam_from_mnemonic_beam);


STATIC mp_obj_t mod_trezorcrypto_beam_export_pkdf(size_t n_args,
                                                  const mp_obj_t* args) {
  mp_buffer_info_t seed;
  mp_get_buffer_raise(args[0], &seed, MP_BUFFER_READ);

  const uint32_t child_idx = (uint32_t)mp_obj_get_uint64_beam(args[1]);
  const uint8_t is_root_key = mp_obj_get_int(args[2]);

  mp_buffer_info_t out_secret;
  mp_get_buffer_raise(args[3], &out_secret, MP_BUFFER_RW);

  mp_buffer_info_t cofactor_G_x;
  mp_buffer_info_t cofactor_G_y;
  mp_get_buffer_raise(args[4], &cofactor_G_x, MP_BUFFER_RW);
  mp_get_buffer_raise(args[5], &cofactor_G_y, MP_BUFFER_RW);

  mp_buffer_info_t cofactor_J_x;
  mp_buffer_info_t cofactor_J_y;
  mp_get_buffer_raise(args[6], &cofactor_J_x, MP_BUFFER_RW);
  mp_get_buffer_raise(args[7], &cofactor_J_y, MP_BUFFER_RW);

  get_pkdf((const uint8_t*)seed.buf,
           child_idx, (bool)is_root_key,
           (uint8_t*)out_secret.buf,
           (uint8_t*)cofactor_G_x.buf, (uint8_t*)cofactor_G_y.buf,
           (uint8_t*)cofactor_J_x.buf, (uint8_t*)cofactor_J_y.buf);

  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_export_pkdf_obj, 8, 8,
    mod_trezorcrypto_beam_export_pkdf);


STATIC mp_obj_t
mod_trezorcrypto_beam_create_master_nonce(size_t n_args, const mp_obj_t* args) {
  mp_buffer_info_t master_nonce;
  mp_get_buffer_raise(args[0], &master_nonce, MP_BUFFER_RW);

  mp_buffer_info_t seed;
  mp_get_buffer_raise(args[1], &seed, MP_BUFFER_READ);

  create_master_nonce((uint8_t*)master_nonce.buf, (uint8_t*)seed.buf);

  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_create_master_nonce_obj, 2, 2,
    mod_trezorcrypto_beam_create_master_nonce);

STATIC mp_obj_t mod_trezorcrypto_beam_create_derived_nonce(
    size_t n_args, const mp_obj_t* args) {
  mp_buffer_info_t master_nonce;
  mp_get_buffer_raise(args[0], &master_nonce, MP_BUFFER_READ);

  uint8_t idx = mp_obj_get_int(args[1]);

  mp_buffer_info_t out_new_nonce;
  mp_get_buffer_raise(args[2], &out_new_nonce, MP_BUFFER_RW);

  create_derived_nonce((const uint8_t*)master_nonce.buf, idx,
                       (uint8_t*)out_new_nonce.buf);

  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_create_derived_nonce_obj, 3, 3,
    mod_trezorcrypto_beam_create_derived_nonce);


STATIC mp_obj_t mod_trezorcrypto_beam_generate_rp_from_cid(
    size_t n_args, const mp_obj_t* args) {
  mp_buffer_info_t seed;
  mp_get_buffer_raise(args[0], &seed, MP_BUFFER_READ);

  const uint64_t idx = mp_obj_get_uint64_beam(args[1]);
  const uint32_t type = mp_obj_get_int(args[2]);
  const uint32_t sub_idx = mp_obj_get_int(args[3]);
  const uint64_t amount = mp_obj_get_uint64_beam(args[4]);
  const uint32_t asset_id = mp_obj_get_int(args[5]);

  BeamCrypto_CoinID cid;
  cid.m_Idx = idx;
  cid.m_Type = type;
  cid.m_SubIdx = sub_idx;
  cid.m_Amount = amount;
  cid.m_AssetID = asset_id;

  mp_buffer_info_t pt0_x;
  mp_get_buffer_raise(args[6], &pt0_x, MP_BUFFER_READ);
  const uint8_t pt0_y = mp_obj_get_int(args[7]);

  mp_buffer_info_t pt1_x;
  mp_get_buffer_raise(args[8], &pt1_x, MP_BUFFER_READ);
  const uint8_t pt1_y = mp_obj_get_int(args[9]);

  const uint8_t use_extra_scalars = mp_obj_get_int(args[10]);

  mp_buffer_info_t extra_sk0;
  mp_get_buffer_raise(args[11], &extra_sk0, MP_BUFFER_READ);

  mp_buffer_info_t extra_sk1;
  mp_get_buffer_raise(args[12], &extra_sk1, MP_BUFFER_READ);

  mp_buffer_info_t out_taux;
  mp_get_buffer_raise(args[13], &out_taux, MP_BUFFER_RW);

  mp_buffer_info_t out_pt0_x;
  mp_get_buffer_raise(args[14], &out_pt0_x, MP_BUFFER_RW);

  mp_buffer_info_t out_pt0_y;
  mp_get_buffer_raise(args[15], &out_pt0_y, MP_BUFFER_RW);

  mp_buffer_info_t out_pt1_x;
  mp_get_buffer_raise(args[16], &out_pt1_x, MP_BUFFER_RW);

  mp_buffer_info_t out_pt1_y;
  mp_get_buffer_raise(args[17], &out_pt1_y, MP_BUFFER_RW);

  const int is_successful = rangeproof_create_from_cid((const uint8_t*)seed.buf,
                                                       &cid,
                                                       (const uint8_t*)pt0_x.buf, pt0_y,
                                                       (const uint8_t*)pt1_x.buf, pt1_y,
                                                       use_extra_scalars,
                                                       (const uint8_t*)extra_sk0.buf,
                                                       (const uint8_t*)extra_sk1.buf,
                                                       (uint8_t*)out_taux.buf,
                                                       (uint8_t*)out_pt0_x.buf, (uint8_t*)out_pt0_y.buf,
                                                       (uint8_t*)out_pt1_x.buf, (uint8_t*)out_pt1_y.buf);

  return mp_obj_new_int(is_successful);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_beam_generate_rp_from_cid_obj, 18, 18,
    mod_trezorcrypto_beam_generate_rp_from_cid);


//
// Type defs
//

// CoinID vtable
STATIC const mp_rom_map_elem_t
    mod_trezorcrypto_beam_coin_id_locals_dict_table[] = {
        {MP_ROM_QSTR(MP_QSTR___del__),
         MP_ROM_PTR(&mod_trezorcrypto_beam_coin_id___del___obj)},
        {MP_ROM_QSTR(MP_QSTR_set),
         MP_ROM_PTR(&mod_trezorcrypto_beam_coin_id_set_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_beam_coin_id_locals_dict,
                            mod_trezorcrypto_beam_coin_id_locals_dict_table);

// CoinID type
STATIC const mp_obj_type_t mod_trezorcrypto_beam_coin_id_type = {
    {&mp_type_type},
    .name = MP_QSTR_CoinID,
    .make_new = mod_trezorcrypto_beam_coin_id_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_beam_coin_id_locals_dict,
};

// TransactionManager vtable
STATIC const mp_rom_map_elem_t
    mod_trezorcrypto_beam_transaction_manager_locals_dict_table[] = {
        {MP_ROM_QSTR(MP_QSTR___del__),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager___del___obj)},
        {MP_ROM_QSTR(MP_QSTR_clear_state),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_clear_state_obj)},
        {MP_ROM_QSTR(MP_QSTR_add_input),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_add_input_obj)},
        {MP_ROM_QSTR(MP_QSTR_add_output),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_add_output_obj)},
        {MP_ROM_QSTR(MP_QSTR_init_keykeeper),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_init_keykeeper_obj)},
        {MP_ROM_QSTR(MP_QSTR_set_common_info),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_set_common_info_obj)},
        {MP_ROM_QSTR(MP_QSTR_set_mutual_info),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_set_mutual_info_obj)},
        {MP_ROM_QSTR(MP_QSTR_set_sender_params),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_set_sender_params_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_send_part_1),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_1_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_send_part_2),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_2_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_send_part_3),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_3_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_send_part_4),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_send_part_4_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_receive),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_receive_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_split_part_1),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_1_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign_transaction_split_part_2),
         MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_sign_transaction_split_part_2_obj)},
        // Getters
        {MP_ROM_QSTR(MP_QSTR_get_tx_aggr_coins_info), MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_get_tx_aggr_coins_info_obj)},
        {MP_ROM_QSTR(MP_QSTR_get_point), MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_get_point_obj)},
        {MP_ROM_QSTR(MP_QSTR_get_scalar), MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_get_scalar_obj)},
         // Point getter types
        {MP_ROM_QSTR(MP_QSTR_TX_COMMON_KERNEL_COMMITMENT), MP_ROM_INT(TX_COMMON_KERNEL_COMMITMENT)},
        {MP_ROM_QSTR(MP_QSTR_TX_COMMON_KERNEL_SIGNATURE_NONCEPUB), MP_ROM_INT(TX_COMMON_KERNEL_SIGNATURE_NONCEPUB)},
        {MP_ROM_QSTR(MP_QSTR_TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_NONCEPUB), MP_ROM_INT(TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_NONCEPUB)},
        // Scalar getter types
        {MP_ROM_QSTR(MP_QSTR_TX_COMMON_KERNEL_SIGNATURE_K), MP_ROM_INT(TX_COMMON_KERNEL_SIGNATURE_K)},
        {MP_ROM_QSTR(MP_QSTR_TX_COMMON_OFFSET_SK), MP_ROM_INT(TX_COMMON_OFFSET_SK)},
        {MP_ROM_QSTR(MP_QSTR_TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_K), MP_ROM_INT(TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_K)},
        {MP_ROM_QSTR(MP_QSTR_TX_SEND_USER_AGREEMENT), MP_ROM_INT(TX_SEND_USER_AGREEMENT)},
        {MP_ROM_QSTR(MP_QSTR_TX_STATE_KERNEL_MSG), MP_ROM_INT(TX_STATE_KERNEL_MSG)},
};
STATIC MP_DEFINE_CONST_DICT(
    mod_trezorcrypto_beam_transaction_manager_locals_dict,
    mod_trezorcrypto_beam_transaction_manager_locals_dict_table);

// TransactionManager type
STATIC const mp_obj_type_t mod_trezorcrypto_beam_transaction_manager_type = {
    {&mp_type_type},
    .name = MP_QSTR_TransactionManager,
    .make_new = mod_trezorcrypto_beam_transaction_manager_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_beam_transaction_manager_locals_dict,
};


STATIC const mp_rom_map_elem_t mod_trezorcrypto_beam_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_beam)},
    {MP_ROM_QSTR(MP_QSTR_from_mnemonic_beam),
     MP_ROM_PTR(&mod_trezorcrypto_beam_from_mnemonic_beam_obj)},
    {MP_ROM_QSTR(MP_QSTR_create_master_nonce),
     MP_ROM_PTR(&mod_trezorcrypto_beam_create_master_nonce_obj)},
    {MP_ROM_QSTR(MP_QSTR_create_derived_nonce),
     MP_ROM_PTR(&mod_trezorcrypto_beam_create_derived_nonce_obj)},
    // NEW CRYPTO
    {MP_ROM_QSTR(MP_QSTR_export_pkdf),
     MP_ROM_PTR(&mod_trezorcrypto_beam_export_pkdf_obj)},
    {MP_ROM_QSTR(MP_QSTR_generate_rp_from_cid),
     MP_ROM_PTR(&mod_trezorcrypto_beam_generate_rp_from_cid_obj)},
    // CoinID
    {MP_ROM_QSTR(MP_QSTR_CoinID),
     MP_ROM_PTR(&mod_trezorcrypto_beam_coin_id_type)},
    // TransactionManager
    {MP_ROM_QSTR(MP_QSTR_TransactionManager),
     MP_ROM_PTR(&mod_trezorcrypto_beam_transaction_manager_type)},
};

STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_beam_globals,
                            mod_trezorcrypto_beam_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_beam_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t*)&mod_trezorcrypto_beam_globals,
};
