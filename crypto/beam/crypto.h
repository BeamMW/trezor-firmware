#ifndef _BEAM_CRYPTO_
#define _BEAM_CRYPTO_

#if defined(LEDGER_SDK)
#include "os.h"
#include "cx.h"
#endif // LEDGER_SDK
#include "debug.h"
#include "beam/definitions.h"
#include "beam/lib/aes/aes.h"

#define BIP32_PATH 5

#if defined(LEDGER_SDK)
typedef cx_sha256_t beam_sha256_ctx;
typedef cx_hmac_sha256_t beam_hmac_sha256_ctx;
#else
#include "hmac.h"
typedef SHA256_CTX beam_sha256_ctx;
typedef HMAC_SHA256_CTX beam_hmac_sha256_ctx;
#endif

#if defined(NATIVE_CRYPT)
typedef cx_aes_key_t beam_aes_ctx;
#else
typedef aes_encrypt_ctx beam_aes_ctx;
#endif


typedef struct
{
  uint8_t margin;
  uint8_t x[32];
  uint8_t y[32];
} pxy_t;

void beam_rng(uint8_t* dest, uint32_t len);
void beam_gej_to_pxy(const secp256k1_gej* gej, pxy_t* pxy);
void beam_pxy_to_point(const pxy_t* pxy, point_t* pt);
void beam_pxy_to_gej(const pxy_t *pxy, secp256k1_gej *pt);
void beam_pxy_mul_scalar(pxy_t *pxy, const secp256k1_scalar *sk);

void beam_pbkdf2_sha512(const uint8_t *password, unsigned short passwordlen, uint8_t *salt,
                        unsigned short saltlen, unsigned int iterations, uint8_t *out, unsigned int outLength);

void beam_hash_sha256_write_8(beam_sha256_ctx *hasher, uint8_t b);
void beam_hash_sha256_write_64(beam_sha256_ctx *hasher, uint64_t v);

void beam_hash_sha256_init(beam_sha256_ctx *hasher);
void beam_hash_sha256_update(beam_sha256_ctx *hasher, const uint8_t *buf, unsigned int len);
int beam_hash_sha256_final(beam_sha256_ctx *hasher, uint8_t *out);

void beam_hash_hmac_sha256_init(beam_hmac_sha256_ctx *hasher, const uint8_t *key, const uint32_t keylen);
void beam_hash_hmac_sha256_update(beam_hmac_sha256_ctx *hasher, const uint8_t *buf, unsigned int len);
int beam_hash_hmac_sha256_final(beam_hmac_sha256_ctx *hasher, uint8_t *out);

void beam_get_private_key_data(uint8_t *data);

void beam_aes_init(beam_aes_ctx *ctx, const uint8_t *key32);
void beam_aes_encrypt(const beam_aes_ctx *ctx, const uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len);

#endif //_BEAM_CRYPTO_
