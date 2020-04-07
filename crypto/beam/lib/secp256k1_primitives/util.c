#include "util.h"

void secp256k1_callback_call(const secp256k1_callback *const cb,
                             const char *const text) {
  cb->fn(text, (void *)cb->data);
}

void *checked_malloc(const secp256k1_callback *cb, size_t size) {
  void *ret = malloc(size);
  if (ret == NULL) {
    secp256k1_callback_call(cb, "Out of memory");
  }
  return ret;
}

int secp256k1_sign_and_abs64(uint64_t *out, int64_t in) {
  uint64_t mask0, mask1;
  int ret;
  ret = in < 0;
  mask0 = ret + ~((uint64_t)0);
  mask1 = ~mask0;
  *out = (uint64_t)in;
  *out = (*out & mask0) | ((~*out + 1) & mask1);
  return ret;
}

int secp256k1_clz64_var(uint64_t x) {
  int ret;
  if (!x) {
    return 64;
  }
#if defined(HAVE_BUILTIN_CLZLL)
  ret = __builtin_clzll(x);
#else
  /*FIXME: debruijn fallback. */
  for (ret = 0; ((x & (1ULL << 63)) == 0); x <<= 1, ret++)
    ;
#endif
  return ret;
}