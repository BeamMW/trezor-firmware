from trezor import ui, utils

from trezor.messages import ButtonRequestType
from trezor.messages.BeamCoinID import BeamCoinID
from trezor.messages.ButtonRequestType import ProtectCall
from trezor.messages.BeamTxCommon import BeamTxCommon

from trezor.ui.scroll import Paginated
from trezor.ui.text import Text

import apps.common.coins as coins

from apps.common.confirm import require_confirm, hold_to_confirm
from apps.common.signverify import split_message
from apps.wallet.sign_tx.layout import confirm_total


def format_amount(value):
    return "%s BEAM" % utils.format_amount(value, 9)


async def require_confirm_sign_message(ctx, message, use_split_message=True):
    await beam_confirm_message(ctx, "Sign BEAM message", message, use_split_message)
    return True


async def require_validate_sign_message(ctx, message):
    message = message.split(" ")
    text = Text("Validate BEAM signature", new_lines=False)
    text.normal(*message)
    await require_confirm(ctx, text)
    return True


async def beam_confirm_message(
    ctx, info_message, message, use_split_message=True, code=None, bold_text=None
):
    if use_split_message:
        message = split_message(message)

    text = Text(info_message, new_lines=False)
    text.normal(*message)
    if bold_text:
        text.bold(bold_text)
    await require_confirm(ctx, text, ProtectCall)


async def beam_ui_msg(ctx, header, message, code=ProtectCall):
    text = Text(header, new_lines=False)
    text.normal(message)
    await require_confirm(ctx, text, code)


async def beam_confirm_tx(ctx, spending, fee):
    coin = coins.by_name("BEAM")
    await confirm_total(ctx, spending, fee, coin)


async def beam_ui_display_kernel_info(ctx, header, kernel):
    page1 = Text(header + " 1/4", ui.ICON_SEND, icon_color=ui.GREEN, new_lines=True)
    page1.normal(ui.GREY, "Fee: ", ui.FG)
    page1.bold(str(kernel.fee))
    page1.normal(ui.GREY, "Height: ", ui.FG)
    page1.bold("{ " + str(kernel.min_height) + "; " + str(kernel.max_height) + " }")

    page2 = Text(header + " 2/4", ui.ICON_SEND, icon_color=ui.GREEN, new_lines=False)
    page2.normal(ui.GREY, "Commitment x: ", ui.FG)
    page2.bold(*split_message(kernel.commitment.x))
    page2.normal(ui.GREY, " y: ", ui.FG)
    page2.bold(str(int(kernel.commitment.y)))

    page3 = Text(header + " 3/4", ui.ICON_SEND, icon_color=ui.GREEN, new_lines=False)
    page3.normal(ui.GREY, "Signature Nonce pub x: ", ui.FG)
    page3.bold(*split_message(kernel.signature.nonce_pub.x))
    page3.normal(ui.GREY, " y: ", ui.FG)
    page3.bold(str(int(kernel.signature.nonce_pub.y)))

    page4 = Text(header + " 4/4", ui.ICON_SEND, icon_color=ui.GREEN, new_lines=False)
    page4.normal(ui.GREY, "Signature Scalar K: ", ui.FG)
    page4.bold(*split_message(kernel.signature.sign_k))

    await require_confirm(ctx, Paginated([page1, page2, page3, page4]), ButtonRequestType.SignTx)


async def require_confirm_transfer(ctx, msg: BeamTxCommon):
    def make_input_output_page(coin: BeamCoinID, page_number, total_pages, direction):
        header = "Confirm " + direction + " ({}/{})".format(str(page_number + 1), str(total_pages))
        coin_page1 = Text(header, ui.ICON_SEND, icon_color=ui.GREEN, new_lines=True)
        coin_page1.normal(ui.GREY, "Idx: ", ui.FG)
        coin_page1.bold(str(coin.idx))
        coin_page1.normal(ui.GREY, "Type: ", ui.FG)
        coin_page1.bold(str(coin.type))

        coin_page2 = Text(header, ui.ICON_SEND, icon_color=ui.GREEN, new_lines=True)
        coin_page2.normal(ui.GREY, "SubIdx: ", ui.FG)
        coin_page2.bold(str(coin.sub_idx))
        if int(coin.asset_id == 0):
            coin_page2.normal(ui.GREY, "Amount:", ui.FG)
            coin_page2.bold(format_amount(coin.amount))
        else:
            coin_page2.normal(ui.GREY, "Amount A{}:".format(str(coin.asset_id)), ui.FG)
            coin_page2.bold(str(coin.amount))

        return [coin_page1, coin_page2]

    pages = []
    for (i, txinput) in enumerate(msg.inputs):
        pages.extend(make_input_output_page(txinput, i, len(msg.inputs), "input"))

    for (i, txoutput) in enumerate(msg.outputs):
        pages.extend(make_input_output_page(txoutput, i, len(msg.outputs), "output"))

    return await hold_to_confirm(ctx, Paginated(pages), ButtonRequestType.ConfirmOutput)


async def require_confirm_tx_aggr(ctx, header, tx_aggr):
    (_, input_assets, _, _, asset_id) = tx_aggr

    text = Text(header, ui.ICON_SEND, icon_color=ui.GREEN, new_lines=True)
    if int(asset_id == 0):
        text.normal(ui.GREY, "Amount:", ui.FG)
        text.bold(format_amount(input_assets))
    else:
        text.normal(ui.GREY, "Amount:", ui.FG)
        text.bold(str(input_assets))
        text.normal(ui.GREY, "Asset ID: ", ui.FG)
        text.bold(str(asset_id))

    return await hold_to_confirm(ctx, text, ButtonRequestType.ConfirmOutput)

