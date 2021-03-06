# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class BeamOwnerKey(p.MessageType):
    MESSAGE_WIRE_TYPE = 908

    def __init__(
        self,
        key: bytes = None,
    ) -> None:
        self.key = key

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('key', p.BytesType, 0),
        }
