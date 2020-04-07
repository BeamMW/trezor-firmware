/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_FIELD_
#define _SECP256K1_FIELD_

/** Field element module.
 *
 *  Field elements can be represented in several ways, but code accessing
 *  it (and implementations) need to take certain properties into account:
 *  - Each field element can be normalized or not.
 *  - Each field element has a magnitude, which represents how far away
 *    its representation is away from normalization. Normalized elements
 *    always have a magnitude of 1, but a magnitude of 1 doesn't imply
 *    normality.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct {
  /* X = sum(i=0..9, elem[i]*2^26) mod n */
  uint32_t n[10];
#ifdef VERIFY
  int magnitude;
  int normalized;
#endif
} secp256k1_fe;

/* Unpacks a constant into a overlapping multi-limbed FE element. */
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0)     \
  {                                                                  \
    (d0) & 0x3FFFFFFUL,                                              \
        (((uint32_t)d0) >> 26) | (((uint32_t)(d1)&0xFFFFFUL) << 6),  \
        (((uint32_t)d1) >> 20) | (((uint32_t)(d2)&0x3FFFUL) << 12),  \
        (((uint32_t)d2) >> 14) | (((uint32_t)(d3)&0xFFUL) << 18),    \
        (((uint32_t)d3) >> 8) | (((uint32_t)(d4)&0x3UL) << 24),      \
        (((uint32_t)d4) >> 2) & 0x3FFFFFFUL,                         \
        (((uint32_t)d4) >> 28) | (((uint32_t)(d5)&0x3FFFFFUL) << 4), \
        (((uint32_t)d5) >> 22) | (((uint32_t)(d6)&0xFFFFUL) << 10),  \
        (((uint32_t)d6) >> 16) | (((uint32_t)(d7)&0x3FFUL) << 16),   \
        (((uint32_t)d7) >> 10)                                       \
  }

#ifdef VERIFY
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0)                    \
  {                                                                           \
    SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), \
        1, 1                                                                  \
  }
#else
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) \
  { SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)) }
#endif

typedef struct {
  uint32_t n[8];
} secp256k1_fe_storage;

#define SECP256K1_FE_STORAGE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) \
  {                                                                \
    { (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }             \
  }
#define SECP256K1_FE_STORAGE_CONST_GET(d) \
  d.n[7], d.n[6], d.n[5], d.n[4], d.n[3], d.n[2], d.n[1], d.n[0]

/** Normalize a field element. */
void secp256k1_fe_normalize(secp256k1_fe *r);

/** Weakly normalize a field element: reduce it magnitude to 1, but don't fully
 * normalize. */
void secp256k1_fe_normalize_weak(secp256k1_fe *r);

/** Normalize a field element, without constant-time guarantee. */
void secp256k1_fe_normalize_var(secp256k1_fe *r);

/** Verify whether a field element represents zero i.e. would normalize to a
 * zero value. The field
 *  implementation may optionally normalize the input, but this should not be
 * relied upon. */
int secp256k1_fe_normalizes_to_zero(secp256k1_fe *r);

/** Verify whether a field element represents zero i.e. would normalize to a
 * zero value. The field
 *  implementation may optionally normalize the input, but this should not be
 * relied upon. */
int secp256k1_fe_normalizes_to_zero_var(secp256k1_fe *r);

/** Set a field element equal to a small integer. Resulting field element is
 * normalized. */
void secp256k1_fe_set_int(secp256k1_fe *r, int a);

/** Sets a field element equal to zero, initializing all fields. */
void secp256k1_fe_clear(secp256k1_fe *a);

/** Verify whether a field element is zero. Requires the input to be normalized.
 */
int secp256k1_fe_is_zero(const secp256k1_fe *a);

/** Check the "oddness" of a field element. Requires the input to be normalized.
 */
int secp256k1_fe_is_odd(const secp256k1_fe *a);

/** Compare two field elements. Requires magnitude-1 inputs. */
int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b);

/** Same as secp256k1_fe_equal, but may be variable time. */
int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b);

/** Compare two field elements. Requires both inputs to be normalized */
int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b);

/** Set a field element equal to 32-byte big endian value. If successful, the
 * resulting field element is normalized. */
int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a);

/** Convert a field element to a 32-byte big endian value. Requires the input to
 * be normalized */
void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a);

/** Set a field element equal to the additive inverse of another. Takes a
 * maximum magnitude of the input
 *  as an argument. The magnitude of the output is one higher. */
void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m);

/** Multiplies the passed field element with a small integer constant.
 * Multiplies the magnitude by that small integer. */
void secp256k1_fe_mul_int(secp256k1_fe *r, int a);

/** Adds a field element to another. The result has the sum of the inputs'
 * magnitudes as magnitude. */
void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a);

/** Sets a field element to be the product of two others. Requires the inputs'
 * magnitudes to be at most 8.
 *  The output magnitude is 1 (but not guaranteed to be normalized). */
void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a,
                      const secp256k1_fe *b);

/** Sets a field element to be the square of another. Requires the input's
 * magnitude to be at most 8. The output magnitude is 1 (but not guaranteed to
 * be normalized). */
void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a);

/** If a has a square root, it is computed in r and 1 is returned. If a does not
 *  have a square root, the root of its negation is computed and 0 is returned.
 *  The input's magnitude can be at most 8. The output magnitude is 1 (but not
 *  guaranteed to be normalized). The result in r will always be a square
 *  itself. */
int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a);

/** Checks whether a field element is a quadratic residue. */
int secp256k1_fe_is_quad_var(const secp256k1_fe *a);

/** Sets a field element to be the (modular) inverse of another. Requires the
 * input's magnitude to be at most 8. The output magnitude is 1 (but not
 * guaranteed to be normalized). */
void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a);

/** Potentially faster version of secp256k1_fe_inv, without constant-time
 * guarantee. */
void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a);

/** Calculate the (modular) inverses of a batch of field elements. Requires the
 * inputs' magnitudes to be at most 8. The output magnitudes are 1 (but not
 * guaranteed to be normalized). The inputs and outputs must not overlap in
 * memory. */
void secp256k1_fe_inv_all_var(secp256k1_fe *r, const secp256k1_fe *a,
                              size_t len);

/** Convert a field element to the storage type. */
void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a);

/** Convert a field element back from the storage type. */
void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r,
                               const secp256k1_fe_storage *a, int flag);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag);

#endif
