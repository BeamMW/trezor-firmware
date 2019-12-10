# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamKeyIDV import BeamKeyIDV

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
        kidv: BeamKeyIDV = None,
        is_public: bool = None,
    ) -> None:
        self.kidv = kidv
        self.is_public = is_public

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('kidv', BeamKeyIDV, 0),
            2: ('is_public', p.BoolType, 0),
        }
