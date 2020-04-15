# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamGetOwnerKey(p.MessageType):
    MESSAGE_WIRE_TYPE = 907

    def __init__(
        self,
        show_display: bool = None,
    ) -> None:
        self.show_display = show_display

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('show_display', p.BoolType, 0),
        }
