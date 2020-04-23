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
    "kernel_params",
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


# DEPRECATED
@expect(messages.BeamSignature)
def sign_message(client, message, kid_idx, kid_sub_idx, show_display=True):
    return client.call(
        messages.BeamSignMessage(
            msg=message,
            kid_idx=int(kid_idx),
            kid_sub_idx=int(kid_sub_idx),
            show_display=show_display,
        )
    )


# DEPRECATED
def verify_message(client, nonce_pub_x, nonce_pub_y, sign_k, pk_x, pk_y, message):
    nonce_pub_x = hex_str_to_bytearray(nonce_pub_x, "Nonce X", True)
    nonce_pub_y = int(nonce_pub_y)
    sign_k = hex_str_to_bytearray(sign_k, "K", True)
    pk_x = hex_str_to_bytearray(pk_x, "PK X", True)
    pk_y = int(pk_y)
    message = normalize_nfc(message)

    try:
        signature = messages.BeamSignature(
            nonce_pub=messages.BeamECCPoint(x=nonce_pub_x, y=nonce_pub_y), sign_k=sign_k
        )
        public_key = messages.BeamECCPoint(x=pk_x, y=pk_y)
        resp = client.call(
            messages.BeamVerifyMessage(
                signature=signature, public_key=public_key, message=message
            )
        )
    except CallException as e:
        resp = e
    if isinstance(resp, messages.Success):
        return True
    return False


# DEPRECATED
@expect(messages.BeamECCPoint)
def get_public_key(client, kid_idx, kid_sub_idx, show_display=True):
    return client.call(
        messages.BeamGetPublicKey(
            kid_idx=int(kid_idx),
            kid_sub_idx=int(kid_sub_idx),
            show_display=show_display,
        )
    )


@expect(messages.BeamOwnerKey)
def get_owner_key(client, show_display=True):
    return client.call(messages.BeamGetOwnerKey(show_display=show_display))


# DEPRECATED
@expect(messages.BeamECCPoint)
def generate_key(client, kidv_idx, kidv_type, kidv_sub_idx, kidv_value, is_coin_key):
    kidv = messages.BeamKeyIDV(
        idx=int(kidv_idx),
        type=int(kidv_type),
        sub_idx=int(kidv_sub_idx),
        value=int(kidv_value),
    )
    return client.call(messages.BeamGenerateKey(kidv=kidv, is_coin_key=is_coin_key))


@expect(messages.BeamECCPoint)
def generate_nonce(client, slot):
    return client.call(messages.BeamGenerateNonce(slot=int(slot)))


@expect(messages.BeamECCPoint)
def get_nonce_image(client, slot):
    return client.call(messages.BeamGetNoncePublic(slot=int(slot)))


@expect(messages.BeamRangeproofData)
def generate_rangeproof(
    client, cid_idx, cid_type, cid_sub_idx, cid_amount, cid_asset_id, pt0_x, pt0_y, pt1_x, pt1_y
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

    return client.call(messages.BeamGenerateRangeproof(cid=cid, pt0=pt0, pt1=pt1))

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
            user_agreement=bytearray(user_agreement, "utf-8"),
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

# DEPRECATED
@session
@expect(messages.BeamSignedTransaction)
def sign_tx(
    client,
    inputs: List[messages.BeamKeyIDV],
    outputs: List[messages.BeamKeyIDV],
    offset_sk,
    nonce_slot,
    kernel_params,
):
    response = client.call(
        messages.BeamSignTransaction(
            inputs=inputs,
            outputs=outputs,
            offset_sk=bytearray(offset_sk, "utf-8"),
            nonce_slot=int(nonce_slot),
            kernel_params=kernel_params,
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
    if signTxType == SignTxType.receive or SignTxType == SignTxType.send:
        _check_required_fields(transaction["tx_mutual_info"], REQUIRED_FIELDS_TX_COMMON, "TxMutualInfo")
        _check_required_fields(
            transaction["tx_mutual_info"]["signature"],
            REQUIRED_FIELDS_TX_COMMON,
            "PaymentProofSignature")
        _check_required_fields(
            transaction["tx_mutual_info"]["signature"]["nonce_pub"],
            REQUIRED_FIELDS_TX_COMMON,
            "PaymentProofSignature - NoncePub")

    for input in transaction["tx_common"]["inputs"]:
        _check_required_fields(input, REQUIRED_FIELDS_COIN_ID, "Input")
    for output in transaction["tx_common"]["outputs"]:
        _check_required_fields(output, REQUIRED_FIELDS_COIN_ID, "Output")

    _check_required_fields(
        transaction["kernel_parameters"],
        REQUIRED_FIELDS_KERNEL_PARAMS,
        "Kernel parameters",
    )
    _check_required_fields(
        transaction["kernel_parameters"]["commitment"],
        REQUIRED_FIELDS_ECC_POINT,
        "Kernel Commitment",
    )
    _check_required_fields(
        transaction["kernel_parameters"]["signature"],
        REQUIRED_FIELDS_SIGNATURE,
        "Kernel Signature",
    )
    _check_required_fields(
        transaction["kernel_parameters"]["signature"]["nonce_pub"],
        REQUIRED_FIELDS_SIGNATURE,
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

    return messages.BeamECCPoint(x=bytearray(point["x"], "utf-8"), y=bool(point["y"]))


def create_signature(signature) -> messages.BeamSignature:
    _check_required_fields(point, REQUIRED_FIELDS_SIGNATURE, "Signature")

    return messages.BeamSignature(
        nonce_pub=create_point(signature["nonce_pub"]),
        sign_k=bytearray(params["k"], "utf-8"),
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
        _check_required_fields(input, REQUIRED_FIELDS_KIDV, "Input")
    for output in params["outputs"]:
        _check_required_fields(output, REQUIRED_FIELDS_KIDV, "Output")

    inputs = [create_coin_id(input) for input in params["inputs"]]
    outputs = [create_coin_id(output) for output in params["outputs"]]

    return messages.BeamTxCommon(
        inputs=inputs,
        offset_sk=bytearray(params["offset_sk"], "utf-8"),
        outputs=outputs,
        kernel_params=create_kernel_params(params["kernel_params"])
    )


def create_tx_mutual_info(params) -> messages.BeamTxMutualInfo:
    _check_required_fields(params, REQUIRED_FIELDS_TX_MUTUAL_INFO, "TxMutualInfo")

    return messages.BeamTxMutualInfo(
        peer=bytearray(params["peer"], "utf-8"),
        wallet_identity_key=int(params["wallet_identity_key"]),
        payment_proof_signature=create_signature(params["payment_proof_signature"]),
    )


def hex_str_to_bytearray(hex_data, name="", print_info=False):
    if hex_data.startswith("0x"):
        hex_data = hex_data[2:]
        if print_info:
            print("Converted {}: {}".format(name, hex_data))

    return bytearray.fromhex(hex_data)
