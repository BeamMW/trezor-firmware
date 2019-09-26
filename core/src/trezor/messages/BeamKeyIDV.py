# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class BeamKeyIDV(p.MessageType):

    def __init__(
        self,
        idx: int = None,
        type: int = None,
        sub_idx: int = None,
        value: int = None,
    ) -> None:
        self.idx = idx
        self.type = type
        self.sub_idx = sub_idx
        self.value = value

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('idx', p.UVarintType, 0),
            2: ('type', p.UVarintType, 0),
            3: ('sub_idx', p.UVarintType, 0),
            4: ('value', p.UVarintType, 0),
        }
