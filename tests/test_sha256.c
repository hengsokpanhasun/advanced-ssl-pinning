/* Known-answer tests for SHA-256 and HMAC-SHA256 (prove the crypto core). */
#include "sha256.h"
#include "hmac_sha256.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;

static int eq_hex(const uint8_t *got, const char *hex) {
  uint8_t want[32];
  size_t i;
  for (i = 0; i < 32; i++) {
    unsigned v;
    sscanf(hex + i * 2, "%2x", &v);
    want[i] = (uint8_t)v;
  }
  return memcmp(got, want, 32) == 0;
}

#define CHECK(cond, name)                               \
  do {                                                  \
    if (cond) {                                         \
      printf("  ok   - %s\n", name);                    \
    } else {                                            \
      printf("  FAIL - %s\n", name);                    \
      fails++;                                          \
    }                                                   \
  } while (0)

int main(void) {
  uint8_t d[32];

  sha256((const uint8_t *)"", 0, d);
  CHECK(eq_hex(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "sha256(\"\")");

  sha256((const uint8_t *)"abc", 3, d);
  CHECK(eq_hex(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "sha256(\"abc\")");

  /* RFC 4231 test case 2 */
  hmac_sha256((const uint8_t *)"Jefe", 4,
              (const uint8_t *)"what do ya want for nothing?", 28, d);
  CHECK(eq_hex(d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        "hmac-sha256 RFC4231 #2");

  printf(fails ? "SHA/HMAC: FAILED (%d)\n" : "SHA/HMAC: all passed\n", fails);
  return fails ? 1 : 0;
}
