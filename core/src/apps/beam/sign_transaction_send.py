import gc
import storage
import apps.beam.helpers as helpers

from trezor import wire

from trezor.crypto import beam

from trezor.messages.BeamSignTransactionSend import BeamSignTransactionSend
from trezor.messages.BeamSignTransactionSendResult import BeamSignTransactionSendResult
from trezor.messages.BeamSignature import BeamSignature
from trezor.messages.BeamECCPoint import BeamECCPoint

from apps.beam.layout import beam_confirm_message, beam_ui_display_kernel_info, require_confirm_transfer, require_confirm_tx_aggr
from apps.beam.nonce import consume_nonce, get_nonce

from ubinascii import hexlify


async def sign_transaction_send(ctx, msg):
    gc.collect()

    # TODO: Confirm inputs/outputs optionally
    #await require_confirm_transfer(ctx, msg.tx_common)

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    helpers.tm_sign_transaction_set_common_info(transaction_manager, msg)
    helpers.tm_sign_transaction_set_mutual_info(transaction_manager, msg)
    parameters_accepted = helpers.tm_sign_transaction_set_sender_params(transaction_manager, msg)
    if not parameters_accepted:
        raise wire.DataError("Sender parameters are invalid")

    # Part 1
    ## TODO: do we need to pass that send_phase at all?
    send_phase = 1
    res = transaction_manager.sign_transaction_send_part_1(send_phase)
    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_SEND)
    helpers.tm_check_status(transaction_manager, res)

    # Part 2
    ## TODO: find better solution to reuse the nonce slot
    fresh_request = not bool(sum(msg.user_agreement))
    nonce_from_slot = get_nonce(msg.nonce_slot) if fresh_request else consume_nonce(msg.nonce_slot)
    if nonce_from_slot is None:
        raise wire.DataError("Invalid nonce slot is provided")

    res = transaction_manager.sign_transaction_send_part_2(nonce_from_slot)
    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_SEND)
    helpers.tm_check_status(transaction_manager, res)

    tx_aggr = transaction_manager.get_tx_aggr_coins_info()
    await beam_confirm_message(ctx, "Confirm peer", "", bold_text=hexlify(msg.tx_mutual_info.peer).decode(),
                               use_split_message=False)
    await require_confirm_tx_aggr(ctx, "Confirm spending", tx_aggr)

    # Part 3
    res = transaction_manager.sign_transaction_send_part_3()
    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_SEND)
    helpers.tm_check_status(transaction_manager, res)

    tx_aggr = transaction_manager.get_tx_aggr_coins_info()
    # TODO: Decide if we should display all kernel params optionally
    await beam_ui_display_kernel_info(ctx, "Confirm send tx", msg.tx_common.kernel_params,
                                      display_fee_and_height_only=True)

    # Part 4
    res = transaction_manager.sign_transaction_send_part_4()
    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_SEND, before_response=True)
    helpers.tm_check_status(transaction_manager, res)

    kernel_msg = helpers.tm_get_scalar(transaction_manager,
                                        transaction_manager.TX_STATE_KERNEL_MSG)
    await beam_confirm_message(ctx, "Verify Kernel ID", "", bold_text=hexlify(kernel_msg).decode(),
                               use_split_message=False)

    return msg

