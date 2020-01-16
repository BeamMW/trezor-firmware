#include <stdio.h>
#include "functions.h"
#include "nonce_generator.h"
#include "internal.h"
#include "misc.h"

context_t CONTEXT;

void init_context(void)
{
  CONTEXT.key.Comission = _FOURCC_FROM(fees);
  CONTEXT.key.Coinbase = _FOURCC_FROM(mine);
  CONTEXT.key.Regular = _FOURCC_FROM(norm);
  CONTEXT.key.Change = _FOURCC_FROM(chng);
  CONTEXT.key.Kernel = _FOURCC_FROM(kern);   // tests only
  CONTEXT.key.Kernel2 = _FOURCC_FROM(kerM);  // used by the miner
  CONTEXT.key.Identity = _FOURCC_FROM(iden); // Node-Wallet auth
  CONTEXT.key.ChildKey = _FOURCC_FROM(SubK);
  CONTEXT.key.Bbs = _FOURCC_FROM(BbsM);
  CONTEXT.key.Decoy = _FOURCC_FROM(dcoy);
  CONTEXT.key.Treasury = _FOURCC_FROM(Tres);

  CONTEXT.generator.G_pts = get_generator_G();
  CONTEXT.generator.J_pts = get_generator_J();
  CONTEXT.generator.H_pts = get_generator_H();
}

context_t *get_context(void) { return &CONTEXT; }

void phrase_to_seed(const char *phrase, const uint32_t phrase_size, uint8_t *out_seed32)
{
  const uint8_t BIP39_MNEMONIC[] = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
  const size_t sizeHash = 512 >> 3;
  const size_t hmacIterations = 2048;
  uint8_t passphrase[sizeof BIP39_MNEMONIC + 4];
  uint8_t hash[sizeHash];

  os_memset(passphrase, 0, sizeof passphrase);
  os_memmove(passphrase, BIP39_MNEMONIC, sizeof BIP39_MNEMONIC);
  beam_pbkdf2_sha512((const uint8_t *)phrase, phrase_size,
                     passphrase, sizeof BIP39_MNEMONIC + 4 /*for round index, set in pbkdf2*/,
                     hmacIterations, hash, sizeHash);
  beam_sha256_ctx ctx;
  beam_hash_sha256_init(&ctx);
  beam_hash_sha256_update(&ctx, hash, sizeHash);
  beam_hash_sha256_final(&ctx, out_seed32);

}

void phrase_to_seed_old(const char *phrase, uint8_t *out_seed32) {
#include "../pbkdf2.h"
  const char salt[] = "mnemonic";
  const size_t sizeHash = 512 >> 3;
  const size_t hmacIterations = 2048;
  uint8_t hash[sizeHash];

  pbkdf2_hmac_sha512((const uint8_t *)phrase, strlen(phrase),
                     (const uint8_t *)salt, strlen(salt), hmacIterations, hash,
                     sizeHash);

  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, hash, sizeHash);
  sha256_Final(&ctx, out_seed32);
}

void seed_to_kdf(const uint8_t *seed, size_t n, uint8_t *out_gen32,
                 secp256k1_scalar *out_cof)
{
  nonce_generator_t secret;
  nonce_generator_init(&secret, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&secret, seed, n);
  nonce_generator_export_output_key(&secret, (const uint8_t *)"gen", 4,
                                    out_gen32);

  nonce_generator_t co_factor;
  nonce_generator_init(&co_factor, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&co_factor, seed, n);
  nonce_generator_export_scalar(&co_factor, (const uint8_t *)"coF", 4, out_cof);
}

void generate_hash_id(uint64_t idx, uint32_t type, uint32_t sub_idx,
                      uint8_t *out32)
{
  beam_sha256_ctx x;
  beam_hash_sha256_init(&x);
  beam_hash_sha256_update(&x, (const uint8_t *)"kid", 4);
  beam_hash_sha256_write_64(&x, idx);
  beam_hash_sha256_write_64(&x, type);
  beam_hash_sha256_write_64(&x, sub_idx);
  beam_hash_sha256_final(&x, out32);
}

void derive_key(const uint8_t *parent, uint8_t parent_size,
                const uint8_t *hash_id, uint8_t id_size, const secp256k1_scalar *cof_sk,
                secp256k1_scalar *out_sk)
{
  secp256k1_scalar a_sk;
  derive_pkey(parent, parent_size, hash_id, id_size, &a_sk);

  secp256k1_scalar_clear(out_sk);
  secp256k1_scalar_mul(out_sk, &a_sk, cof_sk);
}

void derive_pkey(const uint8_t *parent, uint8_t parent_size,
                 const uint8_t *hash_id, uint8_t id_size, secp256k1_scalar *out_sk)
{
  secp256k1_scalar_clear(out_sk);
  nonce_generator_t key;
  nonce_generator_init(&key, (const uint8_t *)"beam-Key", 9);
  nonce_generator_write(&key, parent, parent_size);
  nonce_generator_write(&key, hash_id, id_size);
  nonce_generator_export_scalar(&key, NULL, 0, out_sk);
}

void sk_to_pk(secp256k1_scalar *sk, const secp256k1_gej *generator_pts,
              uint8_t *out32)
{
  secp256k1_gej ptn;
  generator_mul_scalar(&ptn, generator_pts, sk);

  point_t p;
  export_gej_to_point(&ptn, &p);
  if (p.y)
  {
    secp256k1_scalar_negate(sk, sk);
  }

  os_memcpy(out32, p.x, 32);
}

void get_child_kdf(const uint8_t *parent_secret_32, const secp256k1_scalar *parent_cof,
                   uint32_t index, uint8_t *out32_child_secret,
                   secp256k1_scalar *out_child_cof)
{
  if (!index) {
    // by convention 0 is not a child
    os_memcpy(out32_child_secret, parent_secret_32, 32);
    os_memcpy(out_child_cof, parent_cof, sizeof(secp256k1_scalar));
    return;
  }
  uint8_t child_id[32];
  secp256k1_scalar child_key;
  uint8_t child_scalar_data[32];
  generate_hash_id(index, CONTEXT.key.ChildKey, 0, child_id);
  derive_key(parent_secret_32, 32, child_id, 32, parent_cof, &child_key);
  secp256k1_scalar_get_b32(child_scalar_data, &child_key);

  seed_to_kdf(child_scalar_data, 32, out32_child_secret, out_child_cof);
}

uint32_t get_owner_key(const uint8_t *master_key, const secp256k1_scalar *master_cof,
                       const uint8_t *secret, size_t secret_size, uint8_t *out)
{
  uint8_t child_secret_key[32];
  secp256k1_scalar child_cofactor;
  get_child_kdf(master_key, master_cof, 0, child_secret_key, &child_cofactor);

  HKdf_pub_packed_t packed;
  generate_HKdfPub(child_secret_key, &child_cofactor, CONTEXT.generator.G_pts,
                   CONTEXT.generator.J_pts, &packed);

  uint8_t p[sizeof(HKdf_pub_packed_t)];
  os_memcpy(p, &packed, sizeof(HKdf_pub_packed_t));

  return export_encrypted(p, sizeof(HKdf_pub_packed_t), 'P', secret,
                          secret_size, (const uint8_t *)"0", 1, out);
}

void get_HKdf(uint32_t index, const uint8_t *seed, HKdf_t *hkdf)
{
  uint8_t master_secret_key[DIGEST_LENGTH];
  secp256k1_scalar master_cofactor;
  seed_to_kdf(seed, DIGEST_LENGTH, master_secret_key, &master_cofactor);

  HKdf_init(hkdf);
  get_child_kdf(master_secret_key, &master_cofactor, index,
                hkdf->generator_secret, &hkdf->cofactor);
}
