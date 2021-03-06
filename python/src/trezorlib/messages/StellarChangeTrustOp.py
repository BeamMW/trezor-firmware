# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .StellarAssetType import StellarAssetType

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class StellarChangeTrustOp(p.MessageType):
    MESSAGE_WIRE_TYPE = 216

    def __init__(
        self,
        source_account: str = None,
        asset: StellarAssetType = None,
        limit: int = None,
    ) -> None:
        self.source_account = source_account
        self.asset = asset
        self.limit = limit

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source_account', p.UnicodeType, 0),
            2: ('asset', StellarAssetType, 0),
            3: ('limit', p.UVarintType, 0),
        }
