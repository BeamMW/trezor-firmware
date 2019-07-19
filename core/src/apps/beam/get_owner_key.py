from trezor import config, log
from trezor.crypto import beam
from trezor.pin import pin_to_int, show_pin_timeout

from trezor.messages.BeamOwnerKey import BeamOwnerKey
from trezor.messages.Failure import Failure

from apps.common.request_pin import request_pin
from apps.common import layout
from apps.beam.helpers import (
    bin_to_str,
    get_beam_kdf,
)
from apps.beam.layout import *

import ubinascii


async def get_owner_key(ctx, msg):
    if not config.has_pin():
        config.unlock(pin_to_int(""))
        return Failure(message='PIN is not set')
    label = None
    while True:
        pin = await request_pin(label)
        if config.unlock(pin_to_int(pin)):
            break
        else:
            label = "Wrong PIN, enter again"

    export_warning_msg = 'Exposing the key to a third party allows them to see your balance.'
    await beam_confirm_message(ctx, 'Owner key', export_warning_msg, False)
    wait_warning_msg = 'Please wait few seconds until exporting is done'
    await beam_confirm_message(ctx, 'Owner key', wait_warning_msg, False)

    pin = pin.encode()
    owner_key = generate_owner_key(pin)

    if msg.show_display:
        await beam_confirm_message(ctx, 'Owner key', owner_key, True)

    return BeamOwnerKey(key=owner_key)

def generate_owner_key(passphrase, mnemonic = None):
    # AES encoded owner key takes 108 bytes
    owner_key = bytearray(108)
    master_secret, master_cofactor = get_beam_kdf(mnemonic)
    beam.export_owner_key(master_secret, master_cofactor, passphrase, len(passphrase), owner_key)
    owner_key = ubinascii.b2a_base64(owner_key)

    return owner_key

