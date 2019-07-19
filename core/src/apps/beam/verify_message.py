from trezor.crypto import beam
from trezor.messages.Success import Success
from trezor.messages.BeamVerifyMessage import BeamVerifyMessage
from trezor.messages.BeamSignature import BeamSignature

from apps.beam.helpers import (
    bin_to_str,
    is_valid_beam_message,
)
from apps.beam.sign_message import message_digest
from apps.beam.layout import *


async def verify_message(ctx, msg):
    message = message_digest(msg.message)
    if len(msg.signature.nonce_pub.x) != 32 \
       or len(msg.signature.sign_k) != 32:
        raise wire.DataError("Invalid signature")

    is_valid = is_valid_beam_message(msg.signature, msg.public_key, message)
    if not is_valid:
        raise wire.DataError("Invalid signature")

    # Display message itself
    await require_validate_sign_message(ctx, str(msg.message, 'utf-8'))
    # Display pub nonce part
    nonce_msg = 'Sign_x: {}; Sign_y: {};'.format(bin_to_str(msg.signature.nonce_pub.x), msg.signature.nonce_pub.y)
    await require_validate_sign_message(ctx, nonce_msg)
    pubkey_msg = 'Pubkey_x: {}; Pubkey_y: {};'.format(bin_to_str(msg.public_key.x), msg.public_key.y)
    await require_validate_sign_message(ctx, pubkey_msg)
    # Display sign_k part
    sign_k_msg = 'Sign_k: {};'.format(bin_to_str(msg.signature.sign_k))
    await require_validate_sign_message(ctx, sign_k_msg)
    is_valid_msg= 'Is valid: {}.'.format(bool(is_valid))
    await require_validate_sign_message(ctx, is_valid_msg)

    return Success(message="Message verified")

