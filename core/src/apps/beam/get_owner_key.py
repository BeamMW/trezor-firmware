import gc
import ubinascii

from trezor.crypto import beam
from trezor.messages.BeamOwnerKey import BeamOwnerKey

from apps.beam.helpers import get_beam_seed, rand_pswd
from apps.beam.layout import beam_confirm_message


async def get_owner_key(ctx, msg):
    gc.collect()

    export_warning_msg = (
        "Exposing the key to a third party allows them to see your balance."
    )
    await beam_confirm_message(ctx, "Owner key", export_warning_msg, False)
    wait_warning_msg = "Please wait few seconds until exporting is done"
    await beam_confirm_message(ctx, "Owner key", wait_warning_msg, False)

    owner_key = generate_owner_key()

    if msg.show_display:
        await beam_confirm_message(
            ctx, "Owner key", owner_key[:32], True
        )

    return BeamOwnerKey(key=owner_key)


def generate_owner_key(mnemonic=None):
    owner_key = bytearray(32)
    seed = get_beam_seed(mnemonic)
    beam.export_owner_key(seed, owner_key)

    #owner_key = ubinascii.b2a_base64(owner_key)

    return owner_key
