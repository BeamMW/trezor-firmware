from trezor import config
from trezor.crypto import beam

from apps.beam.helpers import beam_app_id


def get_master_nonce_idx():
    return 0


def get_num_nonce_slots():
    return 32


def create_master_nonce(seed):
    master_nonce = bytearray(32)
    beam.create_master_nonce(master_nonce, seed)
    config.set(beam_app_id(), get_master_nonce_idx(), master_nonce)
    for idx in range(1, __get_nonce_idx(get_num_nonce_slots())):
        create_nonce(idx)


def is_master_nonce_created():
    master_nonce = config.get(beam_app_id(), get_master_nonce_idx())
    return master_nonce is not None


def __get_nonce_idx(idx):
    # each passed idx need to have offset 1 as 0 is a master nonce idx
    return idx + 1


def is_valid_nonce_slot(idx):
    return idx != get_master_nonce_idx() and idx < __get_nonce_idx(get_num_nonce_slots())


def create_nonce(idx):
    if is_valid_nonce_slot(idx):
        old_nonce = config.get(beam_app_id(), idx)
        new_nonce = bytearray(32)
        if old_nonce:
            new_nonce = bytearray(old_nonce)
        master_nonce = config.get(beam_app_id(), get_master_nonce_idx())
        beam.create_derived_nonce(master_nonce, idx, new_nonce)
        config.set(beam_app_id(), idx, new_nonce)
        return old_nonce, new_nonce
    return None, None


def calc_nonce_pub(nonce):
    out_nonce_pub_x = bytearray(32)
    out_nonce_pub_y = bytearray(1)
    beam.get_nonce_public_key(nonce, out_nonce_pub_x, out_nonce_pub_y)
    return (out_nonce_pub_x, out_nonce_pub_y)


def consume_nonce(idx):
    idx = __get_nonce_idx(idx)
    old_nonce, _ = create_nonce(idx)
    return old_nonce


def spot_nonce(idx):
    idx = __get_nonce_idx(idx)
    if is_valid_nonce_slot(idx):
        nonce = config.get(beam_app_id(), idx)
        return nonce
    return None


def get_nonce_pub(idx):
    idx = __get_nonce_idx(idx)
    if is_valid_nonce_slot(idx):
        nonce = config.get(beam_app_id(), idx)
        return calc_nonce_pub(nonce)
    return None, None
