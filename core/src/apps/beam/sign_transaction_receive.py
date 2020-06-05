import gc
import storage

import apps.beam.helpers as helpers

from trezor import wire

from trezor.crypto import beam
from trezor.messages.BeamSignTransactionReceiveResult import BeamSignTransactionReceiveResult
from trezor.messages.BeamSignature import BeamSignature
from trezor.messages.BeamECCPoint import BeamECCPoint

#from apps.beam.layout import require_confirm_transfer


async def sign_transaction_receive(ctx, msg):
    gc.collect()

    # Confirm inputs/outputs
    #await require_confirm_transfer(ctx, msg.tx_common)

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    helpers.tm_sign_transaction_set_common_info(transaction_manager, msg)
    helpers.tm_sign_transaction_set_mutual_info(transaction_manager, msg)

    res = transaction_manager.sign_transaction_receive()

    helpers.tm_update_message(transaction_manager, msg, helpers.MESSAGE_TX_RECEIVE, before_response=True)
    helpers.tm_check_status(transaction_manager, res)

    return msg

