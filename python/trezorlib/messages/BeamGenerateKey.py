# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamKeyIDV import BeamKeyIDV

if __debug__:
    try:
        from typing import Dict, List, Optional
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class BeamGenerateKey(p.MessageType):
    MESSAGE_WIRE_TYPE = 809

    def __init__(
        self,
        kidv: BeamKeyIDV = None,
        is_coin_key: bool = None,
    ) -> None:
        self.kidv = kidv
        self.is_coin_key = is_coin_key

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('kidv', BeamKeyIDV, 0),
            2: ('is_coin_key', p.BoolType, 0),
        }
