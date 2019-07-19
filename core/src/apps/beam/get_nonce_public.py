from trezor.messages.BeamGetNoncePublic import BeamGetNoncePublic
from trezor.messages.BeamECCPoint import BeamECCPoint
from trezor.messages.Failure import Failure

from apps.beam.nonce import *
from apps.beam.helpers import (
    get_master_nonce_idx,
)

async def get_nonce_public(ctx, msg):
    idx = msg.slot
    if idx == get_master_nonce_idx() or idx > 255:
        return Failure(message='Incorrect slot provided')

    if not is_master_nonce_created():
        return Failure(message='Nonce Generator is not initialized')

    pubkey_x, pubkey_y = get_nonce_pub(msg.slot)
    return BeamECCPoint(x=pubkey_x, y=int(pubkey_y[0]))
