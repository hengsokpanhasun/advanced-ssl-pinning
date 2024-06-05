/* Minimal, dependency-free SHA-256. */
#ifndef ASPIN_SHA256_H
#define ASPIN_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN 64

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buf[SHA256_BLOCK_LEN];
  size_t buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);

/* One-shot. */
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

#endif
