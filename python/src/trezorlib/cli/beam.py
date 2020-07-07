# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import json

import click
import requests

from .. import beam, tools

# TODO:
PATH_HELP = "BIP-32 path, e.g. m/44'/1533'/0'/0'"

@click.group(name="beam")
def cli():
    """BEAM commands."""


@cli.command(help="Generate key image for the given KIDV")
@click.argument("kidv_idx")
@click.argument("kidv_type")
@click.argument("kidv_sub_idx")
@click.argument("kidv_value")
@click.option("--coin-key", is_flag=True)
@click.pass_obj
def beam_generate_key(connect, kidv_idx, kidv_type, kidv_sub_idx, kidv_value, coin_key):
    client = connect()
    res = beam.generate_key(
        client, kidv_idx, kidv_type, kidv_sub_idx, kidv_value, coin_key
    )

    return res


@cli.command(help="Generate a nonce for the given slot and get its public image")
@click.option(
    "-n",
    "--slot",
    required=True,
    help="Slot where to nonce should be stored. Value should be in range (0, 255)",
)
@click.pass_obj
def generate_nonce(connect, slot):
    client = connect()

    return beam.generate_nonce(client, slot)


@cli.command(help="Get a public image of the nonce for the given slot")
@click.option(
    "-n",
    "--slot",
    required=True,
    help="Slot where to nonce should be stored. Value should be in range (0, 255)",
)
@click.pass_obj
def get_nonce_image(connect, slot):
    client = connect()

    return beam.get_nonce_image(client, slot)


@cli.command(help="Get number of slots available on the device.")
@click.option("-d", "--show-display", is_flag=True)
@click.pass_obj
def get_num_slots(connect, show_display):
    client = connect()
    res = beam.get_num_slots(client, show_display)
    print("Ok")
    print("Received message: {}".format(res))
    return res


@cli.command(help="Get Beam PKdf.")
@click.argument("child_idx")
@click.option("--is-root-key", is_flag=True, default=False)
@click.option("-d", "--show-display", is_flag=True)
@click.pass_obj
def get_pkdf(connect, child_idx, is_root_key, show_display):
    client = connect()
    res = beam.get_pkdf(client, is_root_key, child_idx, show_display)
    print("Ok")
    print("Received message: {}".format(res))
    return res


@cli.command(
    help="Generate and get a rangeproof for the given CoinID"
)
@click.argument("cid_idx")
@click.argument("cid_type")
@click.argument("cid_sub_idx")
@click.argument("cid_amount")
@click.argument("cid_asset_id")
@click.argument("pt0_x")
@click.argument("pt0_y")
@click.argument("pt1_x")
@click.argument("pt1_y")
@click.argument("extra_sk0", required=False)
@click.argument("extra_sk1", required=False)
@click.pass_obj
def generate_rangeproof(
    connect, cid_idx, cid_type, cid_sub_idx, cid_amount, cid_asset_id, pt0_x, pt0_y, pt1_x, pt1_y, extra_sk0, extra_sk1
):
    print("Extra scalars provided:")
    print(extra_sk0)
    print(extra_sk1)
    print("===")
    client = connect()
    return beam.generate_rangeproof(
        client,
        cid_idx, cid_type, cid_sub_idx, cid_amount, cid_asset_id,
        pt0_x, pt0_y,
        pt1_x, pt1_y,
        extra_sk0,
        extra_sk1
    )


@cli.command(help="Sign Beam transaction (Send part)")
@click.option(
    "-f",
    "--file",
    type=click.File("r"),
    required=True,
    help="Transaction in JSON format",
)
@click.pass_obj
def sign_tx_send(connect, file):
    client = connect()

    transaction = json.load(file)
    beam.check_tx_data(transaction, beam.SignTxType.send)

    tx_common = beam.create_tx_common(transaction["tx_common"])
    tx_mutual_info = beam.create_tx_mutual_info(transaction["tx_mutual_info"])

    signed_transaction = beam.sign_tx_send(
        client,
        tx_common,
        tx_mutual_info,
        transaction["nonce_slot"],
        transaction["user_agreement"],
    )

    return signed_transaction


@cli.command(help="Sign Beam transaction (Receive part)")
@click.option(
    "-f",
    "--file",
    type=click.File("r"),
    required=True,
    help="Transaction in JSON format",
)
@click.pass_obj
def sign_tx_receive(connect, file):
    client = connect()

    transaction = json.load(file)
    beam.check_tx_data(transaction, beam.SignTxType.receive)

    tx_common = beam.create_tx_common(transaction["tx_common"])
    tx_mutual_info = beam.create_tx_mutual_info(transaction["tx_mutual_info"])

    signed_transaction = beam.sign_tx_receive(
        client,
        tx_common,
        tx_mutual_info,
    )

    return signed_transaction


@cli.command(help="Sign Beam transaction (Split part)")
@click.option(
    "-f",
    "--file",
    type=click.File("r"),
    required=True,
    help="Transaction in JSON format",
)
@click.pass_obj
def sign_tx_split(connect, file):
    client = connect()

    transaction = json.load(file)
    beam.check_tx_data(transaction, beam.SignTxType.split)

    tx_common = beam.create_tx_common(transaction["tx_common"])

    signed_transaction = beam.sign_tx_split(
        client,
        tx_common,
    )

    return signed_transaction


@cli.command(help="Sign Beam transaction.")
@click.option(
    "-f",
    "--file",
    type=click.File("r"),
    required=True,
    help="Transaction in JSON format",
)
@click.pass_obj
def beam_sign_tx_old(connect, file):
    client = connect()

    transaction = json.load(file)
    beam.check_transaction_data(transaction)

    inputs = [beam.create_kidv(input) for input in transaction["inputs"]]
    outputs = [beam.create_kidv(output) for output in transaction["outputs"]]

    kernel_params = beam.create_kernel_params(transaction["kernel_parameters"])

    signed_transaction = beam.sign_tx(
        client,
        inputs,
        outputs,
        transaction["offset_sk"],
        transaction["nonce_slot"],
        kernel_params,
    )

    return signed_transaction
