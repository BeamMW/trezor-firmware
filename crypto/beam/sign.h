#ifndef _SIGN_H_
#define _SIGN_H_

#include "definitions.h"

void signature_get_challenge(const secp256k1_gej *pt, const uint8_t *msg32,
                             secp256k1_scalar *out_scalar);

void signature_sign_partial(const secp256k1_scalar *multisig_nonce,
                            const secp256k1_gej *multisig_nonce_pub,
                            const uint8_t *msg, const secp256k1_scalar *sk,
                            secp256k1_scalar *out_k);

void signature_sign(const uint8_t *msg32, const secp256k1_scalar *sk,
                    const secp256k1_gej *generator_pts,
                    ecc_signature_t *signature);

int signature_is_valid(const uint8_t *msg32, const ecc_signature_t *signature,
                       const secp256k1_gej *pk,
                       const secp256k1_gej *generator_pts);

#endif // _SIGN_H_
