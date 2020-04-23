import gc

from trezor.crypto import beam
from trezor.messages.BeamSignedTransaction import BeamSignedTransaction

from apps.beam.layout import beam_confirm_message
from apps.beam.nonce import consume_nonce
from apps.common import storage


async def sign_transaction_send(ctx, msg):
    gc.collect()

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    _sign_transaction_set_common_info(transaction_manager, msg)
    _sign_transaction_set_mutual_info(transaction_manager, msg)
    _sign_transaction_set_sender_params(transaction_manager, msg)

    # TODO
    send_phase = 1
    transaction_manager.sign_transaction_send(send_phase)


async def sign_transaction_receive(ctx, msg):
    gc.collect()

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    _sign_transaction_set_common_info(transaction_manager, msg)
    _sign_transaction_set_mutual_info(transaction_manager, msg)

    transaction_manager.sign_transaction_receive()


async def sign_transaction_split(ctx, msg):
    gc.collect()

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    _sign_transaction_set_common_info(transaction_manager, msg)

    transaction_manager.sign_transaction_split()


def _sign_transaction_add_inputs_outputs(transaction_manager, msg):
    for input in msg.inputs:
        cid = beam.CoinID()
        cid.set(input.idx, input.type, input.sub_idx, input.amount, input.asset_id)
        transaction_manager.add_input(kidv)

    for output in msg.outputs:
        cid = beam.KeyIDV()
        cid.set(output.idx, output.type, output.sub_idx, output.amount, output.asset_id)
        transaction_manager.add_output(kidv)


def _sign_transaction_set_common_info(transaction_manager, msg):
    _sign_transaction_add_inputs_outputs(transaction_manager, msg)
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


def _sign_transaction_set_mutual_info(transaction_manager, msg):
    transaction_manager.set_mutual_info(
        msg.tx_mutual_info.peer,
        msg.tx_mutual_info.wallet_identity_key,
        msg.tx_mutual_info.payment_proof_signature.nonce_pub.x,
        msg.tx_mutual_info.payment_proof_signature.nonce_pub.y,
        msg.tx_mutual_info.payment_proof_signature.sign_k,
    )


def _sign_transaction_set_sender_params(transaction_manager, msg):
    transaction_manager.set_sender_params(
        msg.nonce_slot,
        msg.user_agreement,
    )


# DEPRECATED
async def sign_transaction(ctx, msg):
    gc.collect()
    tm = beam.TransactionMaker()
    mnemonic = storage.device.get_mnemonic_secret()

    sk_total, value_transferred = sign_tx_part_1(
        tm,
        mnemonic,
        msg.inputs,
        msg.outputs,
        msg.kernel_params.fee,
        msg.kernel_params.min_height,
        msg.kernel_params.max_height,
        msg.kernel_params.commitment.x,
        msg.kernel_params.commitment.y,
        msg.kernel_params.multisig_nonce.x,
        msg.kernel_params.multisig_nonce.y,
        msg.nonce_slot,
        msg.offset_sk,
    )

    tx_action_message = "RECEIVE" if value_transferred <= 0 else "TRANSFER"
    tx_msg = (
        "Please confirm  "
        + ("receiving " if value_transferred <= 0 else "sending ")
        + str(abs(value_transferred))
        + " Groths"
    )
    await beam_confirm_message(ctx, tx_action_message + ": ", tx_msg, False)

    signature, is_signed = sign_tx_part_2(tm, sk_total, msg.nonce_slot)

    return BeamSignedTransaction(signature=signature)


# DEPRECATED
def sign_tx_part_1(
    transaction_maker,
    mnemonic,
    inputs,
    outputs,
    fee,
    min_height,
    max_height,
    commitment_x,
    commitment_y,
    multisig_nonce_x,
    multisig_nonce_y,
    nonce_slot,
    offset_sk,
):
    transaction_maker.set_transaction_data(
        fee,
        min_height,
        max_height,
        commitment_x,
        commitment_y,
        multisig_nonce_x,
        multisig_nonce_y,
        nonce_slot,
        offset_sk,
    )

    for input in inputs:
        kidv = beam.KeyIDV()
        kidv.set(input.idx, input.type, input.sub_idx, input.value)
        transaction_maker.add_input(kidv)

    for output in outputs:
        kidv = beam.KeyIDV()
        kidv.set(output.idx, output.type, output.sub_idx, output.value)
        transaction_maker.add_output(kidv)

    seed = beam.from_mnemonic_beam(mnemonic)
    sk_total = bytearray(32)

    value_transferred = transaction_maker.sign_transaction_part_1(seed, sk_total)

    return (sk_total, value_transferred)


# DEPRECATED
def sign_tx_part_2(transaction_maker, sk_total, nonce_slot):
    signature = bytearray(32)
    nonce = consume_nonce(nonce_slot)
    is_signed = transaction_maker.sign_transaction_part_2(sk_total, nonce, signature)

    return (signature, is_signed)
