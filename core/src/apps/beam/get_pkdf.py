import gc

from trezor.crypto import beam
from trezor.messages.BeamPKdf import BeamPKdf
from trezor.messages.BeamECCPoint import BeamECCPoint

from apps.beam.helpers import get_beam_seed
from apps.beam.layout import beam_confirm_message

from ubinascii import hexlify


async def get_pkdf(ctx, msg):
    gc.collect()

    # TODO: decide if we need to display a warning
    # If we are dealing with owner key, need to show some warnings
    #if msg.is_root_key:
    #    export_warning_msg = (
    #        "Exposing the key to a third party allows them to see your balance."
    #    )
    #    await beam_confirm_message(ctx, "Owner key", export_warning_msg, False)
    #    wait_warning_msg = "Please wait few seconds until exporting is done"
    #    await beam_confirm_message(ctx, "Owner key", wait_warning_msg, False)
    # If it's not root - only show something if that was requested by host
    if msg.show_display:
        wait_warning_msg = "Please wait few seconds until exporting is done"
        await beam_confirm_message(ctx, "Generate PKdf", wait_warning_msg, False)

    pkdf, cofactor_G, cofactor_J = generate_pkdf(msg.child_idx, msg.is_root_key)

    if msg.show_display:
        await beam_confirm_message(ctx, "PKdf key", "", bold_text=hexlify(pkdf[:32]).decode(),
                                   use_split_message=False)
        await beam_confirm_message(ctx, "PKdf CoFactorG_X", "", bold_text=hexlify(cofactor_G.x[:32]).decode(),
                                   use_split_message=False)
        await beam_confirm_message(ctx, "PKdf CoFactorJ_X", "", bold_text=hexlify(cofactor_J.x[:32]).decode(),
                                   use_split_message=False)

    return BeamPKdf(key=pkdf, cofactor_G=cofactor_G, cofactor_J=cofactor_J)


def generate_pkdf(child_idx, is_root_key,
                  mnemonic=None):
    pkdf = bytearray(32)
    cofactor_G_x = bytearray(32)
    cofactor_G_y = bytearray(1)
    cofactor_J_x = bytearray(32)
    cofactor_J_y = bytearray(1)

    seed = get_beam_seed(mnemonic)
    beam.export_pkdf(seed,
                     child_idx, is_root_key,
                     pkdf,
                     cofactor_G_x, cofactor_G_y,
                     cofactor_J_x, cofactor_J_y)

    return (pkdf,
            BeamECCPoint(x=cofactor_G_x, y=int(cofactor_G_y[0])),
            BeamECCPoint(x=cofactor_J_x, y=int(cofactor_J_y[0])))
