#ifndef _INTERNAL_FUNCTIONS_
#define _INTERNAL_FUNCTIONS_

#include "../hmac.h"
#include "../pbkdf2.h"
#include "../rand.h"
#include "../sha2.h"
#include "definitions.h"

int memis0(const void *p, size_t n);

void memxor(uint8_t *pDst, const uint8_t *pSrc, size_t n);

void assing_aligned(uint8_t *dest, uint8_t *src, size_t bytes);

void sha256_write_8(SHA256_CTX *hash, uint8_t b);

void sha256_write_64(SHA256_CTX *hash, uint64_t v);

int scalar_import_nnz(scalar_t *scalar, const uint8_t *data32);

void scalar_create_nnz(SHA256_CTX *orcale, scalar_t *out_scalar);

int point_import_nnz(secp256k1_gej *gej, const point_t *point);

int point_import(secp256k1_gej *gej, const point_t *point);

void point_create_nnz(SHA256_CTX *oracle, secp256k1_gej *out_gej);

int export_gej_to_point(const secp256k1_gej *native_point, point_t *out_point);

int create_pts(secp256k1_gej *pPts, const secp256k1_gej *in_gpos,
               uint32_t nLevels, SHA256_CTX *oracle);

void generator_mul_scalar(secp256k1_gej *res, const secp256k1_gej *pPts,
                          const scalar_t *sk);

void generate_points(secp256k1_gej *G_pts, secp256k1_gej *J_pts,
                     secp256k1_gej *H_pts);

void signature_get_challenge(const secp256k1_gej *pt, const uint8_t *msg32,
                             scalar_t *out_scalar);

void signature_sign_partial(const scalar_t *multisig_nonce,
                            const secp256k1_gej *multisig_nonce_pub,
                            const uint8_t *msg, const scalar_t *sk,
                            scalar_t *out_k);

void gej_mul_scalar(const secp256k1_gej *pt, const scalar_t *sk,
                    secp256k1_gej *res);

void generate_HKdfPub(const uint8_t *secret_key, const scalar_t *cofactor,
                      const secp256k1_gej *G_pts, const secp256k1_gej *J_pts,
                      HKdf_pub_packed_t *packed);

void xcrypt(const uint8_t *secret_digest, uint8_t *data, size_t mac_value_size,
            size_t data_size);

uint8_t *export_encrypted(const void *p, size_t size, uint8_t code,
                          const uint8_t *secret, size_t secret_size,
                          const uint8_t *meta, size_t meta_size);

#endif  //_INTERNAL_FUNCTIONS_
