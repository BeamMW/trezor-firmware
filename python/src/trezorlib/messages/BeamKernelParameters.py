# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamECCPoint import BeamECCPoint
from .BeamSignature import BeamSignature

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamKernelParameters(p.MessageType):

    def __init__(
        self,
        fee: int = None,
        min_height: int = None,
        max_height: int = None,
        commitment: BeamECCPoint = None,
        signature: BeamSignature = None,
    ) -> None:
        self.fee = fee
        self.min_height = min_height
        self.max_height = max_height
        self.commitment = commitment
        self.signature = signature

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('fee', p.UVarintType, 0),
            2: ('min_height', p.UVarintType, 0),
            3: ('max_height', p.UVarintType, 0),
            4: ('commitment', BeamECCPoint, 0),
            5: ('signature', BeamSignature, 0),
        }
