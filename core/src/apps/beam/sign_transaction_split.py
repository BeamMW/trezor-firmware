import gc
import storage
import apps.beam.helpers as helpers

from trezor.crypto import beam

from trezor.messages.BeamSignTransactionSplit import BeamSignTransactionSplit
from trezor.messages.BeamSignTransactionSplitResult import BeamSignTransactionSplitResult
from trezor.messages.BeamSignature import BeamSignature
from trezor.messages.BeamECCPoint import BeamECCPoint

from apps.beam.layout import beam_confirm_message, beam_ui_display_kernel_info, require_confirm_transfer


async def sign_transaction_split(ctx, msg):
    gc.collect()

    # Confirm inputs/outputs
    await require_confirm_transfer(ctx, msg.tx_common)

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    helpers.tm_sign_transaction_set_common_info(transaction_manager, msg)

    res = transaction_manager.sign_transaction_split_part_1()
    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_SPLIT)
    helpers.tm_check_status(transaction_manager, res)

    kernel_msg = helpers.tm_get_scalar(transaction_manager,
                                        transaction_manager.TX_STATE_KERNEL_MSG)
    await beam_confirm_message(ctx, "Kernel msg: ", kernel_msg, use_split_message=True)
    await beam_ui_display_kernel_info(ctx, "Confirm split tx", msg.tx_common.kernel_params)

    res = transaction_manager.sign_transaction_split_part_2()
    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_SPLIT)
    helpers.tm_check_status(transaction_manager, res)

    return msg

