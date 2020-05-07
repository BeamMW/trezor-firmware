import gc

from trezor.crypto import beam
from trezor.messages.BeamPKdf import BeamPKdf

from apps.beam.helpers import get_beam_seed
from apps.beam.layout import beam_confirm_message


async def get_pkdf(ctx, msg):
    gc.collect()

    # If we are dealing with owner key, need to show some warnings
    if msg.is_root_key:
        export_warning_msg = (
            "Exposing the key to a third party allows them to see your balance."
        )
        await beam_confirm_message(ctx, "Owner key", export_warning_msg, False)
        wait_warning_msg = "Please wait few seconds until exporting is done"
        await beam_confirm_message(ctx, "Owner key", wait_warning_msg, False)
    # If it's not root - only show something if that was requested by host
    elif msg.show_display:
        wait_warning_msg = "Please wait few seconds until exporting is done"
        await beam_confirm_message(ctx, "Generate PKdf", wait_warning_msg, False)

    pkdf = generate_pkdf(msg.child_idx, msg.is_root_key)

    if msg.show_display:
        await beam_confirm_message(ctx, "Generated PKdf", pkdf[:32], True)

    return BeamPKdf(key=pkdf)


def generate_pkdf(child_idx, is_root_key, mnemonic=None):
    pkdf = bytearray(32)
    seed = get_beam_seed(mnemonic)
    beam.export_pkdf(seed, child_idx, is_root_key, pkdf)

    return pkdf
