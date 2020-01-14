#ifndef _ORACLE_H_
#define _ORACLE_H_

#include "definitions.h"
#include "crypto.h"

void sha256_oracle_update_gej(beam_sha256_ctx* oracle, const secp256k1_gej* gej);

void sha256_oracle_update_pt(beam_sha256_ctx* oracle, const point_t* pt);

void sha256_oracle_update_sk(beam_sha256_ctx* oracle, const secp256k1_scalar* sk);

void sha256_oracle_create(beam_sha256_ctx* oracle, uint8_t* out32);

#endif  //_ORACLE_H_
