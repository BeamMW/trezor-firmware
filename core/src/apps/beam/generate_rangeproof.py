import gc

from trezor import wire

from trezor.crypto import beam
from trezor.messages.BeamRangeproofData import BeamRangeproofData
from trezor.messages.BeamECCPoint import BeamECCPoint

import storage


async def generate_rangeproof(ctx, msg):
    gc.collect()

    if len(msg.pt0.x) != 32 or len(msg.pt1.x) != 32:
        raise wire.DataError("Invalid size of points params")

    asset_id = bytearray(0)

    use_extra_scalars = False
    extra_sk0 = bytearray(32)
    extra_sk1 = bytearray(32)
    if msg.extra_sk0 and msg.extra_sk1:
        use_extra_scalars = True
        extra_sk0 = msg.extra_sk0
        extra_sk1 = msg.extra_sk1

        if (len(msg.extra_sk0) != 32 or (len(msg.extra_sk1) != 32)):
            raise wire.DataError("Invalid size of extra scalar params")

    rangeproof_data_taux = bytearray(32)
    rangeproof_out_pt0_x = bytearray(32)
    rangeproof_out_pt0_y = bytearray(1)
    rangeproof_out_pt1_x = bytearray(32)
    rangeproof_out_pt1_y = bytearray(1)

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
        use_extra_scalars,
        extra_sk0,
        extra_sk1,
        rangeproof_data_taux,
        rangeproof_out_pt0_x, rangeproof_out_pt0_y,
        rangeproof_out_pt1_x, rangeproof_out_pt1_y,
    )

    out_pt0 = BeamECCPoint(x=rangeproof_out_pt0_x, y=int(rangeproof_out_pt0_y[0]))
    out_pt1 = BeamECCPoint(x=rangeproof_out_pt1_x, y=int(rangeproof_out_pt1_y[0]))

    return BeamRangeproofData(data_taux=rangeproof_data_taux,
                              is_successful=is_successful,
                              pt0=out_pt0,
                              pt1=out_pt1)
