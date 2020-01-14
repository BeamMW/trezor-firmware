/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille, Gregory Maxwell             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_UTIL_H_
#define _SECP256K1_UTIL_H_
// \n(\s*)VERIFY_CHECK\((.*)\);

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  void (*fn)(const char* text, void* data);
  const void* data;
} secp256k1_callback;

void secp256k1_callback_call(const secp256k1_callback* const cb,
                             const char* const text);

#ifdef DETERMINISTIC
#define TEST_FAILURE(msg)         \
  do {                            \
    fprintf(stderr, "%s\n", msg); \
    abort();                      \
  } while (0);
#else
#define TEST_FAILURE(msg)                                    \
  do {                                                       \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
    abort();                                                 \
  } while (0)
#endif

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x, c) __builtin_expect((x), (c))
#else
#define EXPECT(x, c) (x)
#endif

#ifdef DETERMINISTIC
#define CHECK(cond)                          \
  do {                                       \
    if (EXPECT(!(cond), 0)) {                \
      TEST_FAILURE("test condition failed"); \
    }                                        \
  } while (0)
#else
#define CHECK(cond)                                  \
  do {                                               \
    if (EXPECT(!(cond), 0)) {                        \
      TEST_FAILURE("test condition failed: " #cond); \
    }                                                \
  } while (0)
#endif

/* Like assert(), but when VERIFY is defined, and side-effect safe. */
#if defined(COVERAGE)
#define VERIFY_CHECK(check)
#define VERIFY_SETUP(stmt)
#elif defined(VERIFY)
#define VERIFY_CHECK CHECK
#define VERIFY_SETUP(stmt) \
  do {                     \
    stmt;                  \
  } while (0)
#else
#define VERIFY_CHECK(cond) \
  do {                     \
    (void)(cond);          \
  } while (0)
#define VERIFY_SETUP(stmt)
#endif

void* checked_malloc(const secp256k1_callback* cb, size_t size);

/* Extract the sign of an int64, take the abs and return a uint64, constant
 * time. */
int secp256k1_sign_and_abs64(uint64_t* out, int64_t in);

int secp256k1_clz64_var(uint64_t x);

#endif
