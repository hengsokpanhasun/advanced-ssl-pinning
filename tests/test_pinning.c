/* Behavioural tests for the pinning library. */
#include "aspin.h"
#include "sha256.h"
#include "vectors.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, name)                 \
  do {                                    \
    if (cond) {                           \
      printf("  ok   - %s\n", name);      \
    } else {                              \
      printf("  FAIL - %s\n", name);      \
      fails++;                            \
    }                                     \
  } while (0)

/* A tiny seal/unseal built on a derived key, to show the proof-of-possession
 * idea: provision seals a secret under the key bound to the REAL cert; only the
 * real cert re-derives that key and recovers it. */
static void seal(const uint8_t key[32], const uint8_t *in, uint8_t *out, size_t n) {
  size_t i;
  uint8_t block[32 + 4], stream[32];
  for (i = 0; i < n; i++) {
    if ((i & 31u) == 0) {
      uint32_t ctr = (uint32_t)(i >> 5);
      memcpy(block, key, 32);
      block[32] = (uint8_t)(ctr >> 24); block[33] = (uint8_t)(ctr >> 16);
      block[34] = (uint8_t)(ctr >> 8);  block[35] = (uint8_t)ctr;
      sha256(block, sizeof block, stream);
    }
    out[i] = (uint8_t)(in[i] ^ stream[i & 31u]);
  }
}

int main(void) {
  aspin_ctx *ctx = aspin_create();
  uint8_t kA[32], kA2[32], kB[32], kM[32];
  uint8_t d1[32], d2[32], t1[32], t2[32];

  CHECK(ctx != NULL, "aspin_create");
  if (!ctx) return 1;

  /* --- weak boolean mode --- */
  CHECK(aspin_verify_spki(ctx, SPKI_A, sizeof SPKI_A) == 1, "verify: pinned cert A accepted");
  CHECK(aspin_verify_spki(ctx, SPKI_B, sizeof SPKI_B) == 1, "verify: pinned cert B accepted");
  CHECK(aspin_verify_spki(ctx, SPKI_MITM, sizeof SPKI_MITM) == 0, "verify: MITM cert rejected");

  /* --- hard mode: keys are bound to the presented cert --- */
  aspin_bind_key(ctx, SPKI_A, sizeof SPKI_A, NULL, 0, kA);
  aspin_bind_key(ctx, SPKI_A, sizeof SPKI_A, NULL, 0, kA2);
  aspin_bind_key(ctx, SPKI_B, sizeof SPKI_B, NULL, 0, kB);
  aspin_bind_key(ctx, SPKI_MITM, sizeof SPKI_MITM, NULL, 0, kM);

  CHECK(memcmp(kA, kA2, 32) == 0, "bind_key: deterministic for same cert");
  CHECK(memcmp(kA, kB, 32) != 0, "bind_key: different cert -> different key");
  CHECK(memcmp(kA, kM, 32) != 0, "bind_key: MITM cert -> different key");

  /* --- proof-of-possession: seal under the real cert, try to unseal --- */
  {
    const char *secret = "api-base=https://real.example;token=PROVISIONED";
    size_t n = strlen(secret);
    uint8_t sealed[64], openedA[64], openedM[64];
    seal(kA, (const uint8_t *)secret, sealed, n); /* provisioned under cert A */
    seal(kA, sealed, openedA, n);                 /* real cert re-derives kA */
    seal(kM, sealed, openedM, n);                 /* attacker's MITM key */
    CHECK(memcmp(openedA, secret, n) == 0, "pop: real cert recovers the sealed secret");
    CHECK(memcmp(openedM, secret, n) != 0, "pop: MITM cert yields garbage, not the secret");
  }

  /* --- integrity surfaces are stable within a build --- */
  aspin_self_digest(ctx, d1);
  aspin_self_digest(ctx, d2);
  CHECK(memcmp(d1, d2, 32) == 0, "self_digest stable");
  aspin_text_checksum((const void *)&aspin_bind_key, 96, t1);
  aspin_text_checksum((const void *)&aspin_bind_key, 96, t2);
  CHECK(memcmp(t1, t2, 32) == 0, "text_checksum stable");

  /* --- aspin_spki_pin matches a direct SHA-256 --- */
  {
    uint8_t p1[32], p2[32];
    aspin_spki_pin(SPKI_A, sizeof SPKI_A, p1);
    sha256(SPKI_A, sizeof SPKI_A, p2);
    CHECK(memcmp(p1, p2, 32) == 0, "spki_pin == sha256(spki)");
  }

  aspin_destroy(ctx);
  printf(fails ? "pinning: FAILED (%d)\n" : "pinning: all passed\n", fails);
  return fails ? 1 : 0;
}
