import gc

from trezor import wire

from trezor.crypto import beam
from trezor.messages.BeamRangeproofData import BeamRangeproofData

import storage
from ubinascii import unhexlify


async def generate_rangeproof(ctx, msg):
    gc.collect()

    if len(msg.pt0.x) != 32 or len(msg.pt1.x) != 32:
        raise wire.DataError("Invalid size of points params")

    asset_id = bytearray(0)
    rangeproof_data_taux = bytearray(32)

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    is_successful = beam.generate_rp_from_cid(
        seed,
        msg.cid.idx,
        msg.cid.type,
        msg.cid.sub_idx,
        msg.cid.amount,
        msg.cid.asset_id,
        msg.pt0.x, int(msg.pt0.y),
        msg.pt1.x, int(msg.pt1.y),
        rangeproof_data_taux,
    )

    return BeamRangeproofData(data_taux=rangeproof_data_taux, is_successful=is_successful)
