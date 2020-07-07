from trezor import wire
from trezor.messages import MessageType

# from apps.common import HARDENED

# CURVE = "secp256k1"


def boot() -> None:
    # ns = [[CURVE, HARDENED | 44, HARDENED | 1533]]
    wire.add(MessageType.BeamGetNoncePublic, __name__, "get_nonce_public")
    wire.add(MessageType.BeamGenerateRangeproof, __name__, "generate_rangeproof")
    wire.add(MessageType.BeamGetNumSlots, __name__, "get_num_slots")
    wire.add(MessageType.BeamGetPKdf, __name__, "get_pkdf")
    #wire.add(MessageType.BeamCreateOutput, __name__, "generate_rangeproof")
    wire.add(MessageType.BeamSignTransaction, __name__, "sign_transaction")
    wire.add(MessageType.BeamSignTransactionSend, __name__, "sign_transaction_send")
    wire.add(MessageType.BeamSignTransactionReceive, __name__, "sign_transaction_receive")
    wire.add(MessageType.BeamSignTransactionSplit, __name__, "sign_transaction_split")
