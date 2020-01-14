#ifndef _BEAM_DEBUG_
#define _BEAM_DEBUG_

#if defined (LEDGER_SDK)
#include <stddef.h>
#include <stdint.h>

#define DEBUG_TRY \
  BEGIN_TRY       \
  {               \
    TRY           \
    {

#define END_DEBUG                                                \
  }                                                              \
  CATCH_OTHER(e)                                                 \
  {                                                              \
    printf("DEBUG, ERROR CODE: 0x%.*H \n", 2, ((uint8_t *)&e));  \
    printf("                       0x01  EXCEPTION\n");             \
    printf("                       0x02  INVALID_PARAMETER\n");     \
    printf("                       0x03  EXCEPTION_OVERFLOW\n");    \
    printf("                       0x04  EXCEPTION_SECURITY\n");    \
    printf("                       0x05  INVALID_CRC\n");           \
    printf("                       0x06  INVALID_CHECKSUM\n");      \
    printf("                       0x07  INVALID_COUNTER\n");       \
    printf("                       0x08  NOT_SUPPORTED\n");         \
    printf("                       0x09  INVALID_STATE\n");         \
    printf("                       0x0A TIMEOUT\n");               \
    printf("                       0x0B EXCEPTION_PIC\n");         \
    printf("                       0x0C EXCEPTION_APPEXIT\n");     \
    printf("                       0x0D EXCEPTION_IO_OVERFLOW\n"); \
    printf("                       0x0E EXCEPTION_IO_HEADER\n");   \
    printf("                       0x0F EXCEPTION_IO_STATE\n");    \
    printf("                       0x10 EXCEPTION_IO_RESET\n");    \
    printf("                       0x11 EXCEPTION_CXPORT\n");      \
    printf("                       0x12 EXCEPTION_SYSTEM\n");      \
    printf("                       0x13 NOT_ENOUGH_SPACE\n");      \
  }                                                              \
  FINALLY {}                                                     \
  }                                                              \
  END_TRY;

#define START_TEST(func)                                               \
  do                                                                   \
  {                                                                    \
    printf("|============== Test set has been started: %s\n", #func);  \
    func();                                                            \
    printf("|============== Test set has been finished: %s\n", #func); \
  } while (0)

#define VERIFY_TEST(x)                                                     \
  do                                                                       \
  {                                                                        \
    if (!(x))                                                              \
      printf("|X-> Test failed! Line=%u, Expression: %s\n", __LINE__, #x); \
    else                                                                   \
      printf("|V-> Test passed! Line=%u, Expression: %s\n", __LINE__, #x); \
  } while (0)

#define VERIFY_TEST_EQUAL(x, msg, left_desc, right_desc)                                   \
  do                                                                                       \
  {                                                                                        \
    if (!(x))                                                                              \
      printf("|X-> Test failed!, %s. Expression: %s == %s\n", msg, left_desc, right_desc); \
    else                                                                                   \
      printf("|V-> Test passed!, %s. Expression: %s == %s\n", msg, left_desc, right_desc);  \
  } while (0)

#define VERIFY_TEST(x)                                                     \
  do                                                                       \
  {                                                                        \
    if (!(x))                                                              \
      printf("|X-> Test failed! Line=%u, Expression: %s\n", __LINE__, #x);  \
    else                                                                   \
      printf("|V-> Test passed! Line=%u, Expression: %s\n", __LINE__, #x); \
  } while (0)

#define DEBUG_PRINT(msg, arr, len)              \
  printf("|-   Line=%u, Msg=%s: ", __LINE__, msg); \
  printf("%.*H\n", len, arr);

int IS_EQUAL_HEX(const char* hex_str, const uint8_t* bytes, size_t str_size);

void verify_scalar_data(const char* msg, const char* hex_data, const void* sk);
#else

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define DEBUG_PRINT(msg, arr, len)                                         \
  printf(ANSI_COLOR_CYAN "Line=%u" ANSI_COLOR_RESET ", Msg=%s ", __LINE__, \
         msg);                                                             \
  printf(ANSI_COLOR_YELLOW);                                               \
  for (size_t i = 0; i < len; i++) {                                       \
    printf("%02x", arr[i]);                                                \
  }                                                                        \
  printf(ANSI_COLOR_RESET "\n");

#define CMP_SIMPLE(a, b) \
  if (a < b) return -1;  \
  if (a > b) return 1;

#define CMP_BY_FUN(a, b, cmp_fun)      \
  {                                    \
    const int cmp_res = cmp_fun(a, b); \
    if (cmp_res != 0) return cmp_res;  \
  }

#define CMP_MEMBER(member, other_member) CMP_SIMPLE(member, other_member)

#define CMP_PTRS(a, b, cmp_fun) \
  if (a) {                      \
    if (!b) return 1;           \
    int n = cmp_fun(a, b);      \
    if (n) return n;            \
  } else if (b)                 \
    return -1;
#endif // LEDGER_SDK

#endif //_BEAM_DEBUG_
