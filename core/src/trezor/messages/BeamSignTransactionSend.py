# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .BeamTxCommon import BeamTxCommon
from .BeamTxMutualInfo import BeamTxMutualInfo

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamSignTransactionSend(p.MessageType):
    MESSAGE_WIRE_TYPE = 917

    def __init__(
        self,
        tx_common: BeamTxCommon = None,
        tx_mutual_info: BeamTxMutualInfo = None,
        nonce_slot: int = None,
        user_agreement: bytes = None,
    ) -> None:
        self.tx_common = tx_common
        self.tx_mutual_info = tx_mutual_info
        self.nonce_slot = nonce_slot
        self.user_agreement = user_agreement

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('tx_common', BeamTxCommon, 0),
            2: ('tx_mutual_info', BeamTxMutualInfo, 0),
            3: ('nonce_slot', p.UVarintType, 0),
            4: ('user_agreement', p.BytesType, 0),
        }
