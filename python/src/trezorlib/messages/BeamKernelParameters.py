# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamECCPoint import BeamECCPoint

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class BeamKernelParameters(p.MessageType):

    def __init__(
        self,
        fee: int = None,
        commitment: BeamECCPoint = None,
        min_height: int = None,
        max_height: int = None,
        asset_emission: int = None,
        hash_lock: bytes = None,
        multisig_nonce: BeamECCPoint = None,
        multisig_excess: BeamECCPoint = None,
    ) -> None:
        self.fee = fee
        self.commitment = commitment
        self.min_height = min_height
        self.max_height = max_height
        self.asset_emission = asset_emission
        self.hash_lock = hash_lock
        self.multisig_nonce = multisig_nonce
        self.multisig_excess = multisig_excess

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('fee', p.UVarintType, 0),
            2: ('commitment', BeamECCPoint, 0),
            4: ('min_height', p.UVarintType, 0),
            5: ('max_height', p.UVarintType, 0),
            6: ('asset_emission', p.SVarintType, 0),
            7: ('hash_lock', p.BytesType, 0),
            8: ('multisig_nonce', BeamECCPoint, 0),
            9: ('multisig_excess', BeamECCPoint, 0),
        }
