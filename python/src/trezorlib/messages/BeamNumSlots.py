# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamNumSlots(p.MessageType):
    MESSAGE_WIRE_TYPE = 924

    def __init__(
        self,
        num_slots: int = None,
    ) -> None:
        self.num_slots = num_slots

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('num_slots', p.UVarintType, 0),
        }
