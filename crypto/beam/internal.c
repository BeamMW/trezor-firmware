#include "internal.h"
#include "multi_mac.h"
#include "crypto.h"

int memis0(const void* p, const size_t n)
{
  for (size_t i = 0; i < n; i++)
    if (((const uint8_t*)p)[i]) return 0;
  return 1;
}

void memxor(uint8_t* pDst, const uint8_t* pSrc, const size_t n)
{
  for (size_t i = 0; i < n; i++) pDst[i] ^= pSrc[i];
}

void assign_aligned(uint8_t* dest, uint8_t* src, const size_t bytes)
{
  for (size_t i = bytes; i--; src++) dest[i] = *src;
}

#if ! defined (LEDGER_SDK)
void memzero(uint8_t* dest, const size_t bytes)
{
  memset(dest, 0, bytes);
}
#endif // LEDGER_SDK

int export_gej_to_point(const secp256k1_gej* native_point, point_t* out_point)
{
  if (secp256k1_gej_is_infinity(native_point) != 0)
  {
    os_memset(out_point, 0, sizeof(point_t));
    return 0;
  }

  secp256k1_gej pt = *native_point;
  secp256k1_ge ge;
  secp256k1_ge_set_gej(&ge, &pt);

  // seems like normalization can be omitted (already done by
  // secp256k1_ge_set_gej), but not guaranteed according to docs.
  // But this has a negligible impact on the performance
  secp256k1_fe_normalize(&ge.x);
  secp256k1_fe_normalize(&ge.y);

  secp256k1_fe_get_b32(out_point->x, &ge.x);
  out_point->y = (secp256k1_fe_is_odd(&ge.y) != 0);

  return 1;
}

void generator_mul_scalar(secp256k1_gej *res, const secp256k1_gej *pPts,
                          const secp256k1_scalar *sk)
{
  gej_mul_scalar(pPts, sk, res);
}

void gej_mul_scalar(const secp256k1_gej *pt, const secp256k1_scalar *sk,
                    secp256k1_gej *res)
{
#if defined (LEDGER_SDK)
  pxy_t pt_pxy;
  beam_gej_to_pxy(pt, &pt_pxy);
  printf("gej to pxy");
  beam_pxy_mul_scalar(&pt_pxy, sk);
  printf("pxy mul scalar");
  beam_pxy_to_gej(&pt_pxy, res);
  printf("pxy to gej");
#else
  multi_mac_casual_t mc;
  multi_mac_casual_init(&mc, pt, sk);

  multi_mac_t mm;
  memcpy(mm.casual, &mc, sizeof(mc));
  mm.n_casual = 1;
  mm.n_prepared = 0;
  multi_mac_calculate(&mm, res);
#endif
}

int scalar_import_nnz(secp256k1_scalar *scalar, const uint8_t *data32)
{
  int overflow;
  secp256k1_scalar_set_b32(scalar, data32, &overflow);
  int zero = secp256k1_scalar_is_zero(scalar);
  return !(overflow || zero);
}

void scalar_create_nnz(beam_sha256_ctx *oracle, secp256k1_scalar *out_scalar)
{
  uint8_t data[32];
  secp256k1_scalar_clear(out_scalar);
  do
  {
    beam_sha256_ctx new_oracle;
    os_memcpy(&new_oracle, oracle, sizeof(beam_sha256_ctx));
    beam_hash_sha256_final(&new_oracle, data);
    beam_hash_sha256_update(oracle, data, sizeof(data) / sizeof(data[0]));
  } while (!scalar_import_nnz(out_scalar, data));
}

void generate_HKdfPub(const uint8_t *secret_key, const secp256k1_scalar *cofactor,
                      const secp256k1_gej *G_pts, const secp256k1_gej *J_pts,
                      HKdf_pub_packed_t *packed)
{
  secp256k1_gej pkG;
  secp256k1_gej pkJ;
  generator_mul_scalar(&pkG, G_pts, cofactor);
  generator_mul_scalar(&pkJ, J_pts, cofactor);

  os_memcpy(packed->secret, secret_key, DIGEST_LENGTH);
  export_gej_to_point(&pkG, &packed->pkG);
  export_gej_to_point(&pkJ, &packed->pkJ);
}

void xcrypt(const uint8_t *secret_digest, uint8_t *data, size_t mac_value_size,
            size_t data_size)
{
  uint8_t hvIV[32];
  beam_sha256_ctx x;
  beam_hash_sha256_init(&x);
  beam_hash_sha256_update(&x, secret_digest, DIGEST_LENGTH);
  beam_hash_sha256_final(&x, hvIV);

  beam_hmac_sha256_ctx y;
  beam_hash_hmac_sha256_init(&y, secret_digest, DIGEST_LENGTH);
  beam_hash_hmac_sha256_update(&y, data + mac_value_size, data_size);
  uint8_t cbuf[16];
  os_memcpy(cbuf, hvIV + 16, 16);
  beam_hash_hmac_sha256_final(&y, hvIV);

  beam_aes_ctx ctxe;
  beam_aes_init(&ctxe, secret_digest);
  beam_aes_encrypt(&ctxe, cbuf, data + mac_value_size, data + mac_value_size, data_size);

  os_memcpy(data, hvIV + 32 - mac_value_size, mac_value_size);
}

uint32_t export_encrypted(const void *p, size_t size, uint8_t code,
                           const uint8_t *secret, size_t secret_size,
                           const uint8_t *meta, size_t meta_size, uint8_t *mac_value)
{
  const size_t mac_value_size = 8;
  const size_t data_size = size + 1 + meta_size;
  const size_t buff_size = mac_value_size + data_size;
  os_memset(mac_value, 0, buff_size);

  mac_value[mac_value_size] = code;
  os_memcpy(mac_value + 1 + mac_value_size, p, size);
  os_memcpy(mac_value + 1 + mac_value_size + size, meta, meta_size);

  uint8_t hv_secret[64];
  uint8_t salt[4];
  os_memset(salt, 0, 4);
  beam_pbkdf2_sha512(secret, secret_size, salt, 4, 2048, hv_secret, 64);

  xcrypt(hv_secret, mac_value, mac_value_size, data_size);

  return buff_size;
}

int point_import_nnz(secp256k1_gej *gej, const point_t *point)
{
  if (point->y > 1)
    return 0; // should always be well-formed

  secp256k1_fe nx;
  printf("Try fe_set_b32");
  if (!secp256k1_fe_set_b32(&nx, point->x))
    return 0;

  printf("Try ge_set_xo_var");
  secp256k1_ge ge;
  if (!secp256k1_ge_set_xo_var(&ge, &nx, point->y))
    return 0;

  secp256k1_gej_set_ge(gej, &ge);

  return 1;
}

int point_import(secp256k1_gej *gej, const point_t *point)
{
  if (point_import_nnz(gej, point))
    return 1;

  secp256k1_gej_set_infinity(gej);
  return memis0(point, sizeof(point_t));
}

void point_create_nnz(beam_sha256_ctx* oracle, secp256k1_gej *out_gej)
{
  point_t pt;
  pt.y = 0;

  do
  {
    beam_sha256_ctx new_oracle;
    memcpy(&new_oracle, oracle, sizeof(beam_sha256_ctx));
    beam_hash_sha256_final(&new_oracle, pt.x);
    beam_hash_sha256_update(oracle, pt.x, DIGEST_LENGTH);
  } while (!point_import_nnz(out_gej, &pt));
}

