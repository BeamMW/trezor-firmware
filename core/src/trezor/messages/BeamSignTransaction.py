# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .BeamKernelParametersOld import BeamKernelParametersOld
from .BeamKeyIDV import BeamKeyIDV

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamSignTransaction(p.MessageType):
    MESSAGE_WIRE_TYPE = 914

    def __init__(
        self,
        inputs: List[BeamKeyIDV] = None,
        offset_sk: bytes = None,
        outputs: List[BeamKeyIDV] = None,
        nonce_slot: int = None,
        kernel_params: BeamKernelParametersOld = None,
    ) -> None:
        self.inputs = inputs if inputs is not None else []
        self.offset_sk = offset_sk
        self.outputs = outputs if outputs is not None else []
        self.nonce_slot = nonce_slot
        self.kernel_params = kernel_params

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('inputs', BeamKeyIDV, p.FLAG_REPEATED),
            2: ('offset_sk', p.BytesType, 0),
            3: ('outputs', BeamKeyIDV, p.FLAG_REPEATED),
            4: ('nonce_slot', p.UVarintType, 0),
            5: ('kernel_params', BeamKernelParametersOld, 0),
        }