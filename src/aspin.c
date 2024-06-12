/*
 * Advanced SSL Pinning — core.
 *
 * Design notes (the "skill" this repo demonstrates):
 *   1. Hard mode has NO verdict branch. aspin_bind_key derives a key as
 *          key = HMAC(master, SHA256(presented_pin || self_digest || info))
 *      where `master` is bound to the whole pin table and `self_digest` is bound
 *      to the obfuscated pin/secret bytes. A wrong cert, a patched pin, or a
 *      patched secret all just change the key. There is nothing to flip.
 *   2. The weak boolean mode is constant-time and has no early-exit loop, so the
 *      only patchable point is the caller's use of the final bool — which is the
 *      whole reason hard mode exists.
 *   3. Pins are stored obfuscated (pins.c) so they are not greppable, and the
 *      pins/secrets are folded into self_digest so tampering them is self-defeating.
 */
#include "aspin.h"
#include "pins.h"
#include "sha256.h"
#include "hmac_sha256.h"

#include <stdlib.h>
#include <string.h>

/* Embedded anchor folded into the integrity digest (golden-ratio nothing-up-my-
 * sleeve bytes). Changing it changes every derived key. */
static const uint8_t ASPIN_ANCHOR[16] = {0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a,
                                         0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60,
                                         0x5c, 0xed, 0xc8, 0x34};

struct aspin_ctx {
  uint8_t pins[ASPIN_PIN_COUNT][ASPIN_PIN_LEN];
  uint8_t master[32];      /* HMAC(ROOT, all pins) — bound to the whole table */
  uint8_t self_digest[32]; /* data integrity over obfuscated pins + secrets */
};

static void derive_mask(uint8_t i, uint8_t out[32]) {
  uint8_t buf[ASPIN_SECRET_LEN + 1];
  memcpy(buf, ASPIN_MASK_SECRET, ASPIN_SECRET_LEN);
  buf[ASPIN_SECRET_LEN] = i;
  sha256(buf, sizeof buf, out);
}

static void compute_self_digest(uint8_t out[32]) {
  sha256_ctx c;
  sha256_init(&c);
  sha256_update(&c, (const uint8_t *)ASPIN_MASKED_PINS, sizeof ASPIN_MASKED_PINS);
  sha256_update(&c, ASPIN_MASK_SECRET, ASPIN_SECRET_LEN);
  sha256_update(&c, ASPIN_ROOT_SECRET, ASPIN_SECRET_LEN);
  sha256_update(&c, ASPIN_ANCHOR, sizeof ASPIN_ANCHOR);
  sha256_final(&c, out);
}

/* Constant-time equality: 1 if equal, 0 otherwise. No early exit, no secret
 * branch. The accumulator folds to 0/1 without a conditional. */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t d = 0;
  size_t i;
  for (i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return (int)(1u & (((uint32_t)d - 1u) >> 8)); /* d==0 -> 1, else 0 */
}

aspin_ctx *aspin_create(void) {
  aspin_ctx *ctx = (aspin_ctx *)calloc(1, sizeof *ctx);
  uint8_t mask[32];
  size_t i, j;
  if (!ctx) return NULL;

  for (i = 0; i < ASPIN_PIN_COUNT; i++) {
    derive_mask((uint8_t)i, mask);
    for (j = 0; j < ASPIN_PIN_LEN; j++)
      ctx->pins[i][j] = (uint8_t)(ASPIN_MASKED_PINS[i][j] ^ mask[j]);
  }
  /* master binds the whole (unmasked) table: tamper any pin -> master changes
   * -> every bind_key output changes. */
  hmac_sha256(ASPIN_ROOT_SECRET, ASPIN_SECRET_LEN, (const uint8_t *)ctx->pins,
              sizeof ctx->pins, ctx->master);
  compute_self_digest(ctx->self_digest);

  memset(mask, 0, sizeof mask);
  return ctx;
}

void aspin_destroy(aspin_ctx *ctx) {
  if (ctx) {
    memset(ctx, 0, sizeof *ctx);
    free(ctx);
  }
}

void aspin_spki_pin(const uint8_t *spki, size_t spki_len,
                    uint8_t out[ASPIN_PIN_LEN]) {
  sha256(spki, spki_len, out);
}

int aspin_verify_spki(const aspin_ctx *ctx, const uint8_t *spki, size_t spki_len) {
  uint8_t pin[ASPIN_PIN_LEN];
  unsigned found = 0;
  size_t i;
  if (!ctx || !spki) return 0;

  sha256(spki, spki_len, pin);
  for (i = 0; i < ASPIN_PIN_COUNT; i++) /* OR-accumulate, no early return */
    found |= (unsigned)ct_eq(pin, ctx->pins[i], ASPIN_PIN_LEN);
  memset(pin, 0, sizeof pin);
  return (int)(found & 1u);
}

int aspin_bind_key(const aspin_ctx *ctx, const uint8_t *spki, size_t spki_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t out_key[ASPIN_KEY_LEN]) {
  uint8_t pin[ASPIN_PIN_LEN];
  uint8_t inner[32];
  sha256_ctx s;
  if (!ctx || !spki || !out_key) return -1;

  sha256(spki, spki_len, pin);

  /* inner = SHA256(presented_pin || self_digest || info) */
  sha256_init(&s);
  sha256_update(&s, pin, ASPIN_PIN_LEN);
  sha256_update(&s, ctx->self_digest, sizeof ctx->self_digest);
  if (info && info_len) sha256_update(&s, info, info_len);
  sha256_final(&s, inner);

  /* key = HMAC(master, inner). No branch decided whether the cert was "ok". */
  hmac_sha256(ctx->master, sizeof ctx->master, inner, sizeof inner, out_key);

  memset(pin, 0, sizeof pin);
  memset(inner, 0, sizeof inner);
  return 0;
}

void aspin_self_digest(const aspin_ctx *ctx, uint8_t out[ASPIN_DIGEST_LEN]) {
  memcpy(out, ctx->self_digest, ASPIN_DIGEST_LEN);
}

void aspin_text_checksum(const void *fn, size_t len, uint8_t out[ASPIN_DIGEST_LEN]) {
  sha256((const uint8_t *)fn, len, out);
}
