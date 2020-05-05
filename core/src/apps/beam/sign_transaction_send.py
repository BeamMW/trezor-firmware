import gc
import storage
import apps.beam.helpers as helpers

from trezor import wire

from trezor.crypto import beam
from trezor.messages.BeamSignTransactionSend import BeamSignTransactionSend
from trezor.messages.BeamSignTransactionSendResult import BeamSignTransactionSendResult
from trezor.messages.BeamSignature import BeamSignature
from trezor.messages.BeamECCPoint import BeamECCPoint

#from apps.beam.layout import beam_confirm_message


async def sign_transaction_send(ctx, msg):
    gc.collect()

    #value_transferred = 2
    #tx_action_message = "RECEIVE" if value_transferred <= 0 else "TRANSFER"
    #tx_msg = (
    #    "Please confirm  "
    #    + ("receiving " if value_transferred <= 0 else "sending ")
    #    + str(abs(value_transferred))
    #    + " Groths"
    #)
    #await beam_confirm_message(ctx, tx_action_message + ": ", tx_msg, False)

    mnemonic = storage.device.get_mnemonic_secret()
    seed = beam.from_mnemonic_beam(mnemonic)

    transaction_manager = beam.TransactionManager()
    transaction_manager.init_keykeeper(seed)
    helpers.tm_sign_transaction_set_common_info(transaction_manager, msg)
    helpers.tm_sign_transaction_set_mutual_info(transaction_manager, msg)
    helpers.tm_sign_transaction_set_sender_params(transaction_manager, msg)

    ## TODO
    send_phase = 1
    transaction_manager.sign_transaction_send(send_phase)

    ## Set commitment
    commitment = helpers.tm_get_point(transaction_manager, transaction_manager.TX_COMMON_KERNEL_COMMITMENT)
    kernel_commitment = BeamECCPoint(x=commitment[0], y=commitment[1])
    msg.tx_common.kernel_params.commitment = kernel_commitment
    # Set kernel signature
    kernel_sig_noncepub = helpers.tm_get_point(transaction_manager,
                                               transaction_manager.TX_COMMON_KERNEL_SIGNATURE_NONCEPUB)
    kernel_sig_sk = helpers.tm_get_scalar(transaction_manager,
                                          transaction_manager.TX_COMMON_KERNEL_SIGNATURE_K)
    msg.tx_common.kernel_params.signature = BeamSignature(nonce_pub=BeamECCPoint(x=kernel_sig_noncepub[0],
                                                                                 y=kernel_sig_noncepub[1]),
                                                          sign_k=kernel_sig_sk)
    # Set payment proof signature
    # Set kernel signature
    payment_proof_sig_noncepub = helpers.tm_get_point(transaction_manager,
                                                      transaction_manager.TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_NONCEPUB)
    payment_proof_sig_sk = helpers.tm_get_scalar(transaction_manager,
                                                 transaction_manager.TX_MUTUAL_PAYMENT_PROOF_SIGNATURE_K)
    msg.tx_mutual_info.payment_proof_signature = BeamSignature(nonce_pub=BeamECCPoint(x=payment_proof_sig_noncepub[0],
                                                                                      y=payment_proof_sig_noncepub[1]),
                                                               sign_k=payment_proof_sig_sk)
    # Set user agreement
    user_agreement = helpers.tm_get_scalar(transaction_manager, transaction_manager.TX_SEND_USER_AGREEMENT)
    msg.user_agreement = user_agreement
    # Set offset scalar
    offset_sk = helpers.tm_get_scalar(transaction_manager, transaction_manager.TX_COMMON_OFFSET_SK)
    msg.tx_common.offset_sk = offset_sk
    return msg


    #return msg

