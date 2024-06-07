/* HMAC-SHA256 (RFC 2104). */
#include "hmac_sha256.h"
#include "sha256.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
  uint8_t k[SHA256_BLOCK_LEN];
  uint8_t ipad[SHA256_BLOCK_LEN], opad[SHA256_BLOCK_LEN];
  uint8_t inner[SHA256_DIGEST_LEN];
  sha256_ctx c;
  size_t i;

  memset(k, 0, sizeof(k));
  if (key_len > SHA256_BLOCK_LEN) {
    sha256(key, key_len, k); /* keys longer than the block are hashed down */
  } else {
    memcpy(k, key, key_len);
  }

  for (i = 0; i < SHA256_BLOCK_LEN; i++) {
    ipad[i] = (uint8_t)(k[i] ^ 0x36);
    opad[i] = (uint8_t)(k[i] ^ 0x5c);
  }

  sha256_init(&c);
  sha256_update(&c, ipad, SHA256_BLOCK_LEN);
  sha256_update(&c, msg, msg_len);
  sha256_final(&c, inner);

  sha256_init(&c);
  sha256_update(&c, opad, SHA256_BLOCK_LEN);
  sha256_update(&c, inner, SHA256_DIGEST_LEN);
  sha256_final(&c, out);
}
