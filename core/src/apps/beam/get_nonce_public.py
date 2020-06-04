import gc

from trezor.messages.BeamECCPoint import BeamECCPoint
from trezor.messages.Failure import Failure

from apps.beam.nonce import get_nonce_pub, is_master_nonce_created, is_valid_nonce_slot


async def get_nonce_public(ctx, msg):
    gc.collect()

    idx = msg.slot
    if not is_valid_nonce_slot(idx):
        return Failure(message="Incorrect slot provided")

    if not is_master_nonce_created():
        return Failure(message="Nonce Generator is not initialized")

    pubkey_x, pubkey_y = get_nonce_pub(msg.slot)
    return BeamECCPoint(x=pubkey_x, y=int(pubkey_y[0]))
