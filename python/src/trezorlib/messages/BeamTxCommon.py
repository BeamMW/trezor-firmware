# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BeamCoinID import BeamCoinID
from .BeamKernelParameters import BeamKernelParameters

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BeamTxCommon(p.MessageType):

    def __init__(
        self,
        inputs: List[BeamCoinID] = None,
        offset_sk: bytes = None,
        outputs: List[BeamCoinID] = None,
        kernel_params: BeamKernelParameters = None,
    ) -> None:
        self.inputs = inputs if inputs is not None else []
        self.offset_sk = offset_sk
        self.outputs = outputs if outputs is not None else []
        self.kernel_params = kernel_params

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('inputs', BeamCoinID, p.FLAG_REPEATED),
            2: ('offset_sk', p.BytesType, 0),
            3: ('outputs', BeamCoinID, p.FLAG_REPEATED),
            4: ('kernel_params', BeamKernelParameters, 0),
        }