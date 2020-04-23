# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamSignature import BeamSignature

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamTxMutualInfo(p.MessageType):

    def __init__(
        self,
        peer: bytes = None,
        wallet_identity_key: int = None,
        payment_proof_signature: BeamSignature = None,
    ) -> None:
        self.peer = peer
        self.wallet_identity_key = wallet_identity_key
        self.payment_proof_signature = payment_proof_signature

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('peer', p.BytesType, 0),
            2: ('wallet_identity_key', p.UVarintType, 0),
            3: ('payment_proof_signature', BeamSignature, 0),
        }
