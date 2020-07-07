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

from typing import List

from . import messages
from .tools import CallException, expect, normalize_nfc, session

from enum import Enum


class SignTxType(Enum):
    send = 1
    receive = 2
    split = 3

REQUIRED_FIELDS_ECC_POINT = ["x", "y"]
REQUIRED_FIELDS_COIN_ID = ["idx", "type", "sub_idx", "amount", "asset_id"]
REQUIRED_FIELDS_SIGNATURE = ["nonce_pub", "k"]
REQUIRED_FIELDS_KERNEL_PARAMS = [
    "fee",
    "min_height",
    "max_height",
    "commitment",
    "signature",
]
REQUIRED_FIELDS_TX_COMMON = [
    "inputs",
    "outputs",
    "offset_sk",
    "kernel_parameters",
]
REQUIRED_FIELDS_TX_MUTUAL_INFO = [
    "peer",
    "wallet_identity_key",
    "payment_proof_signature",
]
REQUIRED_FIELDS_TRANSACTION_SEND = [
    "tx_common",
    "tx_mutual_info",
    "nonce_slot",
    "user_agreement",
]
REQUIRED_FIELDS_TRANSACTION_RECEIVE = [
    "tx_common",
    "tx_mutual_info",
]
REQUIRED_FIELDS_TRANSACTION_SPLIT = [
    "tx_common",
]


@expect(messages.BeamNumSlots)
def get_num_slots(client, show_display):
    return client.call(messages.BeamGetNumSlots(show_display=show_display))


@expect(messages.BeamPKdf)
def get_pkdf(client, is_root_key, child_idx, show_display):
    return client.call(messages.BeamGetPKdf(
        is_root_key=is_root_key,
        child_idx=int(child_idx),
        show_display=show_display))


@expect(messages.BeamRangeproofData)
def generate_rangeproof(
    client, cid_idx, cid_type, cid_sub_idx, cid_amount, cid_asset_id, pt0_x, pt0_y, pt1_x, pt1_y, extra_sk0, extra_sk1
):
    cid = messages.BeamCoinID(
        idx=int(cid_idx),
        type=int(cid_type),
        sub_idx=int(cid_sub_idx),
        amount=int(cid_amount),
        asset_id=int(cid_asset_id),
    )
    pt0 = messages.BeamECCPoint(x=bytearray.fromhex(pt0_x), y=int(pt0_y))
    pt1 = messages.BeamECCPoint(x=bytearray.fromhex(pt1_x), y=int(pt1_y))

    if extra_sk0 and extra_sk1:
        extra_sk0=bytearray.fromhex(extra_sk0)
        extra_sk1=bytearray.fromhex(extra_sk1)

    return client.call(
        messages.BeamGenerateRangeproof(cid=cid,
                                        pt0=pt0,
                                        pt1=pt1,
                                        extra_sk0=extra_sk0,
                                        extra_sk1=extra_sk1,
        )
    )


@session
#@expect(messages.BeamSignTransactionSendResult)
def sign_tx_send(
    client,
    tx_common,
    tx_mutual_info,
    nonce_slot,
    user_agreement,
):
    response = client.call(
        messages.BeamSignTransactionSend(
            tx_common=tx_common,
            tx_mutual_info=tx_mutual_info,
            nonce_slot=nonce_slot,
            user_agreement=hex_str_to_bytearray(user_agreement),
        )
    )
    return response

@session
#@expect(messages.BeamSignTransactionReceiveResult)
def sign_tx_receive(
    client,
    tx_common,
    tx_mutual_info,
):
    response = client.call(
        messages.BeamSignTransactionReceive(
            tx_common=tx_common,
            tx_mutual_info=tx_mutual_info,
        )
    )
    return response

@session
#@expect(messages.BeamSignTransactionSendResult)
def sign_tx_split(
    client,
    tx_common,
):
    response = client.call(
        messages.BeamSignTransactionSplit(
            tx_common=tx_common,
        )
    )
    return response


def _check_required_fields(data, required_fields, error_message):
    missing_fields = [field for field in required_fields if field not in data.keys()]

    if missing_fields:
        raise ValueError(
            error_message
            + ": The structure is missing some fields: "
            + str(missing_fields)
        )


def check_tx_data(transaction, signTxType):
    required_fields = []
    if signTxType == SignTxType.send:
        required_fields = REQUIRED_FIELDS_TRANSACTION_SEND
    elif signTxType == SignTxType.receive:
        required_fields = REQUIRED_FIELDS_TRANSACTION_RECEIVE
    elif signTxType == SignTxType.split:
        required_fields = REQUIRED_FIELDS_TRANSACTION_SPLIT
    else:
        raise ValueError("Wrong SignTxType passed")

    _check_required_fields(
        transaction,
        required_fields,
        "The transaction is missing some fields",
    )

    _check_required_fields(transaction["tx_common"], REQUIRED_FIELDS_TX_COMMON, "TxCommon")
    if signTxType == SignTxType.receive or signTxType == SignTxType.send:
        _check_required_fields(transaction["tx_mutual_info"], REQUIRED_FIELDS_TX_MUTUAL_INFO, "TxMutualInfo")
        _check_required_fields(
            transaction["tx_mutual_info"]["payment_proof_signature"],
            REQUIRED_FIELDS_SIGNATURE,
            "PaymentProofSignature")
        _check_required_fields(
            transaction["tx_mutual_info"]["payment_proof_signature"]["nonce_pub"],
            REQUIRED_FIELDS_ECC_POINT,
            "PaymentProofSignature - NoncePub")

    for input in transaction["tx_common"]["inputs"]:
        _check_required_fields(input, REQUIRED_FIELDS_COIN_ID, "Input")
    for output in transaction["tx_common"]["outputs"]:
        _check_required_fields(output, REQUIRED_FIELDS_COIN_ID, "Output")

    _check_required_fields(
        transaction["tx_common"]["kernel_parameters"],
        REQUIRED_FIELDS_KERNEL_PARAMS,
        "Kernel parameters",
    )
    _check_required_fields(
        transaction["tx_common"]["kernel_parameters"]["commitment"],
        REQUIRED_FIELDS_ECC_POINT,
        "Kernel Commitment",
    )
    _check_required_fields(
        transaction["tx_common"]["kernel_parameters"]["signature"],
        REQUIRED_FIELDS_SIGNATURE,
        "Kernel Signature",
    )
    _check_required_fields(
        transaction["tx_common"]["kernel_parameters"]["signature"]["nonce_pub"],
        REQUIRED_FIELDS_ECC_POINT,
        "Kernel Signature - NoncePub",
    )


def create_coin_id(cid) -> messages.BeamCoinID:
    _check_required_fields(cid, REQUIRED_FIELDS_COIN_ID, "Input/Output")

    return messages.BeamCoinID(
        idx=int(cid["idx"]),
        type=int(cid["type"]),
        sub_idx=int(cid["sub_idx"]),
        amount=int(cid["amount"]),
        asset_id=int(cid["asset_id"]),
    )


def create_point(point) -> messages.BeamECCPoint:
    _check_required_fields(point, REQUIRED_FIELDS_ECC_POINT, "ECC Point")

    return messages.BeamECCPoint(x=hex_str_to_bytearray(point["x"]), y=bool(point["y"]))


def create_signature(signature) -> messages.BeamSignature:
    _check_required_fields(signature, REQUIRED_FIELDS_SIGNATURE, "Signature")

    return messages.BeamSignature(
        nonce_pub=create_point(signature["nonce_pub"]),
        sign_k=hex_str_to_bytearray(signature["k"]),
    )


def create_kernel_params(params) -> messages.BeamKernelParameters:
    _check_required_fields(params, REQUIRED_FIELDS_KERNEL_PARAMS, "Kernel parameters")

    return messages.BeamKernelParameters(
        fee=int(params["fee"]),
        min_height=int(params["min_height"]),
        max_height=int(params["max_height"]),
        commitment=create_point(params["commitment"]),
        signature=create_signature(params["signature"]),
    )


def create_tx_common(params) -> messages.BeamTxCommon:
    _check_required_fields(params, REQUIRED_FIELDS_TX_COMMON, "TxCommon")

    for input in params["inputs"]:
        _check_required_fields(input, REQUIRED_FIELDS_COIN_ID, "Input")
    for output in params["outputs"]:
        _check_required_fields(output, REQUIRED_FIELDS_COIN_ID, "Output")

    inputs = [create_coin_id(input) for input in params["inputs"]]
    outputs = [create_coin_id(output) for output in params["outputs"]]

    return messages.BeamTxCommon(
        inputs=inputs,
        offset_sk=hex_str_to_bytearray(params["offset_sk"]),
        outputs=outputs,
        kernel_params=create_kernel_params(params["kernel_parameters"])
    )


def create_tx_mutual_info(params) -> messages.BeamTxMutualInfo:
    _check_required_fields(params, REQUIRED_FIELDS_TX_MUTUAL_INFO, "TxMutualInfo")

    return messages.BeamTxMutualInfo(
        peer=hex_str_to_bytearray(params["peer"]),
        wallet_identity_key=int(params["wallet_identity_key"]),
        payment_proof_signature=create_signature(params["payment_proof_signature"]),
    )


def hex_str_to_bytearray(hex_data, name="", print_info=False):
    if hex_data.startswith("0x"):
        hex_data = hex_data[2:]
        if print_info:
            print("Converted {}: {}".format(name, hex_data))

    return bytearray.fromhex(hex_data)
