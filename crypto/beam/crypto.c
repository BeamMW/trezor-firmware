#include "crypto.h"
#include "internal.h"
#include "rand.h"


void beam_gej_to_pxy(const secp256k1_gej *gej, pxy_t *pxy)
{
  secp256k1_gej pt = *gej;
  secp256k1_ge ge;
  secp256k1_ge_set_gej(&ge, &pt);

  // seems like normalization can be omitted (already done by
  // secp256k1_ge_set_gej), but not guaranteed according to docs.
  // But this has a negligible impact on the performance
  secp256k1_fe_normalize(&ge.x);
  secp256k1_fe_normalize(&ge.y);

  pxy->margin = 0x04;
  secp256k1_fe_get_b32(pxy->x, &ge.x);
  secp256k1_fe_get_b32(pxy->y, &ge.y);
}

void beam_pxy_to_point(const pxy_t *pxy, point_t *pt)
{
  os_memcpy(pt->x, pxy->x, DIGEST_LENGTH);
  secp256k1_fe y;
  secp256k1_fe_set_b32(&y, pxy->y);
  pt->y = (secp256k1_fe_is_odd(&y) != 0);
}

void beam_pxy_to_gej(const pxy_t *pxy, secp256k1_gej *pt)
{
  secp256k1_ge ge;
  secp256k1_fe_set_b32(&ge.x, pxy->x);
  secp256k1_fe_set_b32(&ge.y, pxy->y);
  ge.infinity = 0;
  secp256k1_gej_set_ge(pt, &ge);
}

void beam_pxy_mul_scalar(pxy_t *pxy, const secp256k1_scalar *sk)
{
#if defined (LEDGER_SDK)
  uint8_t scalar[DIGEST_LENGTH];
  secp256k1_scalar_get_b32(scalar, sk);
  cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, (uint8_t*)pxy, sizeof(pxy_t), scalar, DIGEST_LENGTH);
#else
  secp256k1_gej pt;
  beam_pxy_to_gej(pxy, &pt);
  gej_mul_scalar(&pt, sk, &pt);
  beam_gej_to_pxy(&pt, pxy);
#endif // LEDGER_SDK
}

void beam_pbkdf2_sha512(const uint8_t *password, unsigned short password_len, uint8_t *salt,
                        unsigned short salt_len, unsigned int num_iterations, uint8_t *out_hash, unsigned int out_hash_len)
{

#if defined (LEDGER_SDK)
  cx_pbkdf2_sha512(password, password_len, salt, salt_len, num_iterations, out_hash, out_hash_len);
#else
#include "pbkdf2.h"
  pbkdf2_hmac_sha512(password, password_len, salt, salt_len, num_iterations, out_hash, out_hash_len);
#endif // LEDGER_SDK
}

void beam_hash_sha256_write_8(beam_sha256_ctx *hasher, uint8_t b)
{
  beam_hash_sha256_update(hasher, &b, sizeof(b));
}

void beam_hash_sha256_write_64(beam_sha256_ctx *hasher, uint64_t v)
{
  for (; v >= 0x80; v >>= 7) {
    beam_hash_sha256_write_8(hasher, (uint8_t)((uint8_t)v | 0x80));
  }

  beam_hash_sha256_write_8(hasher, (uint8_t)v);
}

void beam_hash_sha256_init(beam_sha256_ctx *hasher)
{
#if defined (LEDGER_SDK)
  cx_sha256_init(hasher);
#else
  sha256_Init(hasher);
#endif // LEDGER_SDK
}

void beam_hash_sha256_update(beam_sha256_ctx *hasher, const uint8_t *buf, unsigned int len)
{
#if defined (LEDGER_SDK)
  cx_hash((cx_hash_t *)hasher, 0, buf, len, NULL, 0);
#else
  sha256_Update(hasher, buf, len);
#endif // LEDGER_SDK
}

int beam_hash_sha256_final(beam_sha256_ctx *hasher, uint8_t *out)
{
#if defined (LEDGER_SDK)
  return cx_hash((cx_hash_t *)hasher, CX_LAST, NULL, 0, out, DIGEST_LENGTH);
#else
  sha256_Final(hasher, out);
  return 0;
#endif // LEDGER_SDK
}

void beam_hash_hmac_sha256_init(beam_hmac_sha256_ctx *hasher, const uint8_t *key, const uint32_t keylen)
{
#if defined (LEDGER_SDK)
  cx_hmac_sha256_init(hasher, key, keylen);
#else
  hmac_sha256_Init(hasher, key, keylen);
#endif // LEDGER_SDK
}

void beam_hash_hmac_sha256_update(beam_hmac_sha256_ctx *hasher, const uint8_t *buf, unsigned int len)
{
#if defined (LEDGER_SDK)
  cx_hmac((cx_hash_t *)hasher, 0, buf, len, NULL, 0);
#else
  hmac_sha256_Update(hasher, buf, len);
#endif // LEDGER_SDK
}

int beam_hash_hmac_sha256_final(beam_hmac_sha256_ctx *hasher, uint8_t *out)
{
#if defined (LEDGER_SDK)
  return cx_hmac((cx_hash_t *)hasher, CX_LAST, NULL, 0, out, DIGEST_LENGTH);
#else
  hmac_sha256_Final(hasher, out);
  return 0;
#endif // LEDGER_SDK
}

void beam_get_private_key_data(uint8_t *data)
{
  uint32_t HARDENED_OFFSET = 0x80000000;
  uint32_t derivePath[BIP32_PATH] = {
      44 | HARDENED_OFFSET,
      1533 | HARDENED_OFFSET,
      0 | HARDENED_OFFSET,
      0 | HARDENED_OFFSET,
      0 | HARDENED_OFFSET};

#if defined (LEDGER_SDK)
  os_perso_derive_node_bip32(CX_CURVE_SECP256K1, derivePath, BIP32_PATH, data, NULL);
#else
  //TODO: use derive Path
  UNUSED(derivePath);
  // Test data
  os_memset(data, 3, DIGEST_LENGTH);
#endif // LEDGER_SDK
}

void beam_aes_init(beam_aes_ctx* ctx, const uint8_t* key32)
{
#if defined (NATIVE_CRYPT)
  cx_aes_init_key(key32, DIGEST_LENGTH, ctx);
#else
  aes_encrypt_key256(key32, ctx);
#endif
}

void beam_aes_encrypt(const beam_aes_ctx *ctx, const uint8_t *iv16, const uint8_t *in, uint8_t *out, uint32_t len)
{
#if defined(NATIVE_CRYPT)
  cx_aes_iv(ctx, CX_ENCRYPT | CX_CHAIN_CTR | CX_LAST | CX_PAD_NONE,
            iv16, 16, in, len, out, len);
#else
  aes_ctr_encrypt(in, out, len, (uint8_t*)iv16, aes_ctr_cbuf_inc, (beam_aes_ctx*)ctx);
#endif
}

void beam_rng(uint8_t* dest, uint32_t len)
{
#if defined (LEDGER_SDK)
  cx_rng(dest, len);
#else
  random_buffer(dest, len);
#endif // LEDGER_SDK
}
