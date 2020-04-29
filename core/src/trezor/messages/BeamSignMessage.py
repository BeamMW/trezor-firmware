# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamSignMessage(p.MessageType):
    MESSAGE_WIRE_TYPE = 902

    def __init__(
        self,
        msg: str = None,
        kid_idx: int = None,
        kid_sub_idx: int = None,
        show_display: bool = None,
    ) -> None:
        self.msg = msg
        self.kid_idx = kid_idx
        self.kid_sub_idx = kid_sub_idx
        self.show_display = show_display

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('msg', p.UnicodeType, 0),
            2: ('kid_idx', p.UVarintType, 0),
            3: ('kid_sub_idx', p.UVarintType, 0),
            4: ('show_display', p.BoolType, 0),
        }