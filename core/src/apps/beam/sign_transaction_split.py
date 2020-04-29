import gc
import storage
import apps.beam.helpers as helpers

from trezor.crypto import beam
from trezor.messages.BeamSignTransactionSplit import BeamSignTransactionSplitResult

from apps.beam.layout import beam_confirm_message
from apps.beam.nonce import consume_nonce


async def sign_transaction_split(ctx, msg):
    gc.collect()

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    helpers._sign_transaction_set_common_info(transaction_manager, msg)

    transaction_manager.sign_transaction_split()


