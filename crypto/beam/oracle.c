#include "oracle.h"
#include "internal.h"

void sha256_oracle_update_gej(beam_sha256_ctx* oracle, const secp256k1_gej* gej)
{
    point_t pt;
    export_gej_to_point(gej, &pt);
    sha256_oracle_update_pt(oracle, &pt);
}

void sha256_oracle_update_pt(beam_sha256_ctx* oracle, const point_t* pt)
{
    beam_hash_sha256_update(oracle, pt->x, 32);
    beam_hash_sha256_write_8(oracle, pt->y);
}

void sha256_oracle_update_sk(beam_sha256_ctx* oracle, const secp256k1_scalar* sk)
{
    uint8_t sk_bytes[32];
    memset(sk_bytes, 0, 32);
    secp256k1_scalar_get_b32(sk_bytes, sk);
    beam_hash_sha256_update(oracle, sk_bytes, 32);
}

void sha256_oracle_create(beam_sha256_ctx* oracle, uint8_t* out32)
{
    beam_sha256_ctx new_oracle;
    memcpy(&new_oracle, oracle, sizeof(beam_sha256_ctx));
    beam_hash_sha256_final(&new_oracle, out32);
    beam_hash_sha256_update(oracle, out32, 32);
}
