# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamTxCommon import BeamTxCommon

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamSignTransactionSplit(p.MessageType):

    def __init__(
        self,
        tx_common: BeamTxCommon = None,
    ) -> None:
        self.tx_common = tx_common

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('tx_common', BeamTxCommon, 0),
        }
