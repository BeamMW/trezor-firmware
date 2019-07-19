/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SCALAR_32_
#define _SCALAR_32_

#include <stdint.h>

/** A scalar modulo the group order of the secp256k1 curve. */
typedef struct {
    uint32_t d[8];
} scalar_t;

/** Clear a scalar to prevent the leak of sensitive data. */
void scalar_clear(scalar_t *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
unsigned int scalar_get_bits(const scalar_t *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
unsigned int scalar_get_bits_var(const scalar_t *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. */
void scalar_set_b32(scalar_t *r, const unsigned char *bin, int *overflow);

/** Set a scalar to an unsigned integer. */
void scalar_set_int(scalar_t *r, unsigned int v);

/** Set a scalar to an unsigned 64-bit integer */
void scalar_set_u64(scalar_t *r, uint64_t v);

/** Convert a scalar to a byte array. */
void scalar_get_b32(unsigned char *bin, const scalar_t *a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
int scalar_add(scalar_t *r, const scalar_t *a, const scalar_t *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
void scalar_cadd_bit(scalar_t *r, unsigned int bit, int flag);

/** Multiply two scalars (modulo the group order). */
void scalar_mul(scalar_t *r, const scalar_t *a, const scalar_t *b);

/** Shift a scalar right by some amount strictly between 0 and 16, returning
 *  the low bits that were shifted off */
int scalar_shr_int(scalar_t *r, int n);

/** Compute the square of a scalar (modulo the group order). */
void scalar_sqr(scalar_t *r, const scalar_t *a);

/** Compute the inverse of a scalar (modulo the group order). */
void scalar_inverse(scalar_t *r, const scalar_t *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
void scalar_inverse_var(scalar_t *r, const scalar_t *a);

/** Compute the complement of a scalar (modulo the group order). */
void scalar_negate(scalar_t *r, const scalar_t *a);

/** Check whether a scalar equals zero. */
int scalar_is_zero(const scalar_t *a);

/** Check whether a scalar equals one. */
int scalar_is_one(const scalar_t *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
int scalar_is_even(const scalar_t *a);

/** Check whether a scalar is higher than the group order divided by 2. */
int scalar_is_high(const scalar_t *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
int scalar_cond_negate(scalar_t *a, int flag);

/** Compare two scalars. */
int scalar_eq(const scalar_t *a, const scalar_t *b);

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
void scalar_mul_shift_var(scalar_t *r, const scalar_t *a, const scalar_t *b, unsigned int shift);

#endif // _SCALAR_32_
