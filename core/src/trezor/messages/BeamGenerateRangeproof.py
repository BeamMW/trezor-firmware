# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .BeamCoinID import BeamCoinID
from .BeamECCPoint import BeamECCPoint

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamGenerateRangeproof(p.MessageType):
    MESSAGE_WIRE_TYPE = 912

    def __init__(
        self,
        cid: BeamCoinID = None,
        pt0: BeamECCPoint = None,
        pt1: BeamECCPoint = None,
    ) -> None:
        self.cid = cid
        self.pt0 = pt0
        self.pt1 = pt1

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('cid', BeamCoinID, 0),
            2: ('pt0', BeamECCPoint, 0),
            3: ('pt1', BeamECCPoint, 0),
        }