import gc

from trezor.messages.BeamNumSlots import BeamNumSlots
from trezor.messages.Failure import Failure

from apps.beam.nonce import is_master_nonce_created


async def get_num_slots(ctx, msg):
    gc.collect()

    if not is_master_nonce_created():
        return Failure(message="No Slots are available. Nonce Generator is not initialized")

    return BeamNumSlots(num_slots=32)
