import apps.common.coins as coins

from trezor import ui
from trezor.ui.text import Text

from apps.common.confirm import *
from apps.common.layout import *
from apps.common.signverify import split_message
from apps.wallet.sign_tx.layout import confirm_total

async def require_confirm_sign_message(ctx, message, use_split_message=True):
    await beam_confirm_message(ctx, 'Sign BEAM message', message, use_split_message)
    return True

async def require_validate_sign_message(ctx, message):
    message = message.split(' ')
    text = Text('Validate BEAM signature', new_lines=False)
    text.normal(*message)
    await require_confirm(ctx, text)
    #await beam_confirm_message(ctx, 'Validate BEAM signature', message)
    return True

async def beam_confirm_message(ctx, info_message, message, use_split_message=True):
    if use_split_message:
        message = split_message(message)

    text = Text(info_message, new_lines=False)
    text.normal(*message)
    await require_confirm(ctx, text)

async def beam_confirm_tx(ctx, spending, fee):
    coin = coins.by_name('BEAM')
    await confirm_total(ctx, spending, fee, coin)
