from trezor.messages.BeamECCPoint import BeamECCPoint

from apps.common import layout
from apps.beam.helpers import (
    bin_to_str,
    get_beam_pk,
)


async def get_public_key(ctx, msg):
    pubkey_x, pubkey_y = get_beam_pk(msg.kid_idx, msg.kid_sub_idx)

    if msg.show_display:
        await layout.show_pubkey(ctx, pubkey_x)
    if msg.show_display:
        await layout.show_pubkey(ctx, pubkey_y)

    return BeamECCPoint(x=pubkey_x, y=pubkey_y)
