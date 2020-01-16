#include "sign.h"
#include "crypto.h"
#include "internal.h"
#include "nonce_generator.h"
#include "misc.h"

void signature_get_challenge(const secp256k1_gej *pt, const uint8_t *msg32,
                             secp256k1_scalar *out_scalar)
{
  point_t p;
  secp256k1_gej point;
  os_memcpy(&point, pt, sizeof(secp256k1_gej));
  export_gej_to_point(&point, &p);

  beam_sha256_ctx oracle;
  beam_hash_sha256_init(&oracle);
  beam_hash_sha256_update(&oracle, p.x, 32);
  beam_hash_sha256_update(&oracle, &p.y, 1);
  beam_hash_sha256_update(&oracle, msg32, 32);

  scalar_create_nnz(&oracle, out_scalar);
}

void signature_sign_partial(const secp256k1_scalar *multisig_nonce,
                            const secp256k1_gej *multisig_nonce_pub,
                            const uint8_t *msg, const secp256k1_scalar *sk,
                            secp256k1_scalar *out_k)
{
  signature_get_challenge(multisig_nonce_pub, msg, out_k);

  secp256k1_scalar_mul(out_k, out_k, sk);
  secp256k1_scalar_add(out_k, out_k, multisig_nonce);
  secp256k1_scalar_negate(out_k, out_k);
}

void signature_sign(const uint8_t *msg32, const secp256k1_scalar *sk,
                    const secp256k1_gej *generator_pts,
                    ecc_signature_t *signature)
{
  nonce_generator_t secret;
  uint8_t bytes[32];

  secp256k1_scalar_get_b32(bytes, sk);

  nonce_generator_init(&secret, (const uint8_t *)"beam-Schnorr", 13);
  nonce_generator_write(&secret, bytes, DIGEST_LENGTH);

#ifdef BEAM_DEBUG
  test_set_buffer(bytes, 32, DIGEST_LENGTH);
#else
  beam_rng(bytes, sizeof(bytes) / sizeof(bytes[0])); // add extra
                                                   // randomness to the
                                                   // nonce, so it's
                                                   // derived from both
                                                   // deterministic and
                                                   // random parts
#endif // BEAM_DEBUG
  nonce_generator_write(&secret, bytes, DIGEST_LENGTH);

  secp256k1_scalar multisig_nonce;
  nonce_generator_export_scalar(&secret, NULL, 0, &multisig_nonce);
  generator_mul_scalar(&signature->nonce_pub, generator_pts, &multisig_nonce);

  signature_sign_partial(&multisig_nonce, &signature->nonce_pub, msg32, sk,
                         &signature->k);
}

int signature_is_valid(const uint8_t *msg32, const ecc_signature_t *signature,
                       const secp256k1_gej *pk,
                       const secp256k1_gej *generator_pts)
{
  secp256k1_scalar e;
  signature_get_challenge(&signature->nonce_pub, msg32, &e);
  printf("Got challenge");

  secp256k1_gej pt;
  generator_mul_scalar(&pt, generator_pts, &signature->k);
  printf("Got scalar");

  secp256k1_gej mul_pt;
  gej_mul_scalar(pk, &e, &mul_pt);
  printf("gej_mul_scalar done");
  secp256k1_gej_add_var(&pt, &pt, &mul_pt, NULL);
  printf("gej_add_var done");
  secp256k1_gej_add_var(&pt, &pt, &signature->nonce_pub, NULL);
  printf("gej_add_var done");

  return secp256k1_gej_is_infinity(&pt) != 0;
}
