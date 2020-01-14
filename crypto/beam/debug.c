#include <stdio.h>
#include <stdint.h>

#include "debug.h"
#include "os.h"
#include "utils.h"

#include "beam/definitions.h"
#include "lib/secp256k1_primitives/scalar.h"

int IS_EQUAL_HEX(const char* hex_str, const uint8_t* bytes, size_t str_size)
{
    uint8_t tmp[str_size / 2];
    hex2bin(tmp, hex_str, str_size);
    return os_memcmp(tmp, bytes, str_size / 2) == 0;
}

void verify_scalar_data(const char* msg, const char* hex_data,
                        const void* sk) {
    uint8_t sk_data[DIGEST_LENGTH];
    secp256k1_scalar_get_b32(sk_data, (secp256k1_scalar*)sk);
    DEBUG_PRINT(msg, sk_data, DIGEST_LENGTH);
    VERIFY_TEST_EQUAL(IS_EQUAL_HEX(hex_data, sk_data, DIGEST_LENGTH), msg,
                      hex_data, "sk");
}
