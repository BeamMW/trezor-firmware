import gc

from trezor.messages.BeamNumSlots import BeamNumSlots
from trezor.messages.Failure import Failure

from apps.beam.nonce import is_master_nonce_created
from apps.beam.layout import beam_confirm_message


async def get_num_slots(ctx, msg):
    gc.collect()

    if not is_master_nonce_created():
        return Failure(message="No Slots are available. Nonce Generator is not initialized")

    num_slots = __get_num_nonce_slots()
    if msg.show_display:
        await beam_confirm_message(ctx, "Nonce slots", "Number of available nonce slots is " + str(num_slots), False)

    return BeamNumSlots(num_slots=num_slots)


def __get_num_nonce_slots():
    return 32
