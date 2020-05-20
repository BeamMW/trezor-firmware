import storage

from apps.common import mnemonic

from trezor import wire
from trezor.crypto import beam, random
from trezor.messages.BeamSignature import BeamSignature
from trezor.messages.BeamECCPoint import BeamECCPoint

from ubinascii import unhexlify

MESSAGE_TX_SPLIT = const(1)
MESSAGE_TX_RECEIVE = const(2)
MESSAGE_TX_SEND = const(3)

STATUS_OK = const(0)
STATUS_UNSPECIFIED = const(1)
STATUS_USER_ABORT = const(2)
STATUS_NOT_IMPL = const(3)


def BBS_KEY():
    return 1113748301


def beam_app_id():
    return 19


def get_master_nonce_idx():
    return 0


def bin_to_str(binary_data):
    return "".join("{:02x}".format(x) for x in binary_data)


def get_beam_seed(mnemonic_phrase=None):
    if not storage.is_initialized():
        raise wire.NotInitialized("Device is not initialized")

    if mnemonic_phrase is None:
        # Get kdf
        mnemonic_phrase = mnemonic.get_secret()
    seed = beam.from_mnemonic_beam(mnemonic_phrase)
    return seed


def get_beam_kdf(mnemonic_phrase=None):
    if not storage.is_initialized():
        raise wire.NotInitialized("Device is not initialized")

    if mnemonic_phrase is None:
        # Get kdf
        mnemonic_phrase = mnemonic.get_secret()
    seed = beam.from_mnemonic_beam(mnemonic_phrase)
    seed_size = 32
    secret_key = bytearray(32)
    cofactor = bytearray(32)
    beam.seed_to_kdf(seed, seed_size, secret_key, cofactor)
    return (secret_key, cofactor)


def get_beam_sk(kid_idx, kid_sub_idx=0, kdf=None):
    # Generate hash id
    kid_type = BBS_KEY()
    hash_id = bytearray(32)
    beam.generate_hash_id(kid_idx, kid_type, kid_sub_idx, hash_id)

    if kdf is None:
        # Get kdf
        secret_key, cofactor = get_beam_kdf()
    else:
        secret_key, cofactor = kdf

    # Derive key
    res_sk = bytearray(32)
    beam.derive_child_key(secret_key, 32, hash_id, 32, cofactor, res_sk)

    return res_sk


def get_beam_pk(kid_idx, kid_sub_idx=0, kdf=None):
    # Secret key to public key
    public_key_x = bytearray(32)
    public_key_y = bytearray(1)
    sk = get_beam_sk(kid_idx, kid_sub_idx, kdf)
    beam.secret_key_to_public_key(sk, public_key_x, public_key_y)

    return (public_key_x, int(public_key_y[0]))


def is_valid_beam_message(signature, public_key, message):
    is_valid = beam.is_valid_signature(
        message,
        signature.nonce_pub.x,
        int(signature.nonce_pub.y),
        signature.sign_k,
        public_key.x,
        int(public_key.y),
    )

    return is_valid


def rand_pswd(size=8):
    """Generate a random password of fixed length """
    charset = "12346789ACDEFGHJKLMNPQRTUVWXYabcdefghijkmnopqrstuvwxyz"
    return "".join(charset[random.uniform(len(charset))] for _ in range(size))


def get_status_description(status):
    if status == STATUS_OK:
        return "Beam: OK"
    if status == STATUS_UNSPECIFIED:
        return "Beam: Unspecified error"
    if status == STATUS_USER_ABORT:
        return "Beam: UserAbort error"
    if status == STATUS_NOT_IMPL:
        return "Beam: NotImpl error"

    return "Beam: UNDEFINED error"


def require_ok_status(status):
    if status != STATUS_OK:
        raise wire.FirmwareError(get_status_description(status))


###
### TRANSACTION MANAGER HELPERS
###

def hexarr2bin(hex_bytearray):
    hex_str = str(hex_bytearray, 'hex')
    if len(hex_str) < 2:
        raise ValueError("Bad input for hexarr2bin!")

    if hex_str[0:2] == "0x":
        hex_str = hex_str[2:]
    return unhexlify(hex_str)


def tm_sign_transaction_add_inputs_outputs(transaction_manager, msg):
    for input in msg.tx_common.inputs:
        cid = beam.CoinID()
        cid.set(input.idx, input.type, input.sub_idx, input.amount, input.asset_id)
        transaction_manager.add_input(cid)

    for output in msg.tx_common.outputs:
        cid = beam.CoinID()
        cid.set(output.idx, output.type, output.sub_idx, output.amount, output.asset_id)
        transaction_manager.add_output(cid)


def tm_sign_transaction_set_common_info(transaction_manager, msg):
    tm_sign_transaction_add_inputs_outputs(transaction_manager, msg)
    transaction_manager.set_common_info(
        msg.tx_common.kernel_params.fee,
        msg.tx_common.kernel_params.min_height,
        msg.tx_common.kernel_params.max_height,
        msg.tx_common.kernel_params.commitment.x,
        msg.tx_common.kernel_params.commitment.y,
        msg.tx_common.kernel_params.signature.nonce_pub.x,
        msg.tx_common.kernel_params.signature.nonce_pub.y,
        msg.tx_common.kernel_params.signature.sign_k,
        msg.tx_common.offset_sk,
    )


def tm_sign_transaction_set_mutual_info(transaction_manager, msg):
    transaction_manager.set_mutual_info(
        msg.tx_mutual_info.peer,
        msg.tx_mutual_info.wallet_identity_key,
        msg.tx_mutual_info.payment_proof_signature.nonce_pub.x,
        msg.tx_mutual_info.payment_proof_signature.nonce_pub.y,
        msg.tx_mutual_info.payment_proof_signature.sign_k,
    )


def tm_sign_transaction_set_sender_params(transaction_manager, msg):
    transaction_manager.set_sender_params(
        msg.nonce_slot,
        msg.user_agreement,
    )


def tm_get_point(transaction_manager, point_type):
    point_x = bytearray(32)
    point_y = bytearray(1)
    res = transaction_manager.get_point(point_type, point_x, point_y)

    if res != 0:
        print("tm_get_point: wrong point type provided!")

    return (point_x, int(point_y[0]))


def tm_get_scalar(transaction_manager, scalar_type):
    scalar_data = bytearray(32)
    res = transaction_manager.get_scalar(scalar_type, scalar_data)

    if res != 0:
        print("tm_get_scalar: wrong scalar type provided!")

    return scalar_data


def tm_update_message_common_params(transaction_manager, msg):
    # Set commitment
    commitment = tm_get_point(transaction_manager, transaction_manager.TX_COMMON_KERNEL_COMMITMENT)
    kernel_commitment = BeamECCPoint(x=commitment[0], y=commitment[1])
    msg.tx_common.kernel_params.commitment = kernel_commitment

    # Set kernel signature
    kernel_sig_noncepub = tm_get_point(transaction_manager,
                                       transaction_manager.TX_COMMON_KERNEL_SIGNATURE_NONCEPUB)
    kernel_sig_sk = tm_get_scalar(transaction_manager,
                                  transaction_manager.TX_COMMON_KERNEL_SIGNATURE_K)
    msg.tx_common.kernel_params.signature = BeamSignature(nonce_pub=BeamECCPoint(x=kernel_sig_noncepub[0],
                                                                                 y=kernel_sig_noncepub[1]),
                                                          sign_k=kernel_sig_sk)

    # Set offset scalar
    offset_sk = tm_get_scalar(transaction_manager, transaction_manager.TX_COMMON_OFFSET_SK)
    msg.tx_common.offset_sk = offset_sk


def tm_update_message_mutual_params(transaction_manager, msg):
    # Set payment proof signature
    # Set kernel signature
    payment_proof_sig_noncepub = tm_get_point(transaction_manager,
                                              transaction_manager.TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_NONCEPUB)
    payment_proof_sig_sk = tm_get_scalar(transaction_manager,
                                         transaction_manager.TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_K)
    msg.tx_mutual_info.payment_proof_signature = BeamSignature(nonce_pub=BeamECCPoint(x=payment_proof_sig_noncepub[0],
                                                                                      y=payment_proof_sig_noncepub[1]),
                                                               sign_k=payment_proof_sig_sk)


def tm_update_message_sender_params(transaction_manager, msg):
    # Set user agreement
    user_agreement = tm_get_scalar(transaction_manager, transaction_manager.TX_SEND_USER_AGREEMENT)
    msg.user_agreement = user_agreement


def tm_update_message(transaction_manager, msg, message_type):
    if message_type == MESSAGE_TX_SPLIT or message_type == MESSAGE_TX_RECEIVE or message_type == MESSAGE_TX_SEND:
        tm_update_message_common_params(transaction_manager, msg)
    if message_type == MESSAGE_TX_RECEIVE or message_type == MESSAGE_TX_SEND:
        tm_update_message_mutual_params(transaction_manager, msg)
    if message_type == MESSAGE_TX_SEND:
        tm_update_message_sender_params(transaction_manager, msg)


# Need to be called to ensure no possible sensitive data is left in the memory
def tm_finish(transaction_manager):
    transaction_manager.clear_state()


def tm_check_status(transaction_manager, status):
    if status != STATUS_OK:
        tm_finish(transaction_manager)
        raise wire.FirmwareError(get_status_description(status))
