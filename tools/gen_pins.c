/*
 * gen_pins — turn a DER SubjectPublicKeyInfo into an obfuscated pin entry for
 * src/pins.c.
 *
 *   gen_pins <index> <spki.der>
 *
 * Prints the masked 32-byte row:  masked[j] = SHA256(spki)[j] ^ mask(index)[j],
 * mask(i) = SHA256("aspin/mask/v1" || i). Paste the row into ASPIN_MASKED_PINS
 * at position <index>. Extract an SPKI with, e.g.:
 *   openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der > spki.der
 */
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>

static const char MASK_SECRET[] = "aspin/mask/v1";

int main(int argc, char **argv) {
  FILE *f;
  long sz;
  unsigned char *buf, pin[32], mask[32], msk[32];
  unsigned idx;
  int j;
  unsigned char seed[sizeof(MASK_SECRET)]; /* secret bytes (no NUL) + index */

  if (argc != 3) {
    fprintf(stderr, "usage: %s <index 0-255> <spki.der>\n", argv[0]);
    return 2;
  }
  idx = (unsigned)strtoul(argv[1], NULL, 10);

  f = fopen(argv[2], "rb");
  if (!f) { perror("open"); return 1; }
  fseek(f, 0, SEEK_END);
  sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz <= 0) { fprintf(stderr, "empty file\n"); fclose(f); return 1; }
  buf = (unsigned char *)malloc((size_t)sz);
  if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
    fprintf(stderr, "read error\n"); fclose(f); free(buf); return 1;
  }
  fclose(f);

  sha256(buf, (size_t)sz, pin);

  /* mask(idx) = SHA256(MASK_SECRET || idx) over the 13 secret bytes + 1 index */
  for (j = 0; j < 13; j++) seed[j] = (unsigned char)MASK_SECRET[j];
  seed[13] = (unsigned char)idx;
  sha256(seed, 14, msk);
  for (j = 0; j < 32; j++) mask[j] = msk[j];

  printf("    {/* masked pin[%u] */\n     ", idx);
  for (j = 0; j < 32; j++) {
    printf("0x%02x,", pin[j] ^ mask[j]);
    printf((j % 12 == 11 || j == 31) ? "\n     " : " ");
  }
  printf("},\n");

  free(buf);
  return 0;
}
