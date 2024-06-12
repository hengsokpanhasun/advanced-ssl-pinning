/*
 * Obfuscated pin set.
 *
 * Each 32-byte SHA-256 SPKI pin is stored XOR-masked with
 *     mask[i] = SHA-256(ASPIN_MASK_SECRET || i)[0:32]
 * so no plaintext pin ever appears in .rodata. `strings`, a byte-scan for a
 * 32-byte table, or diffing against a published pin set all come up empty; the
 * pins exist in cleartext only briefly in RAM, inside aspin_create().
 *
 * NOTE: obfuscation only raises the bar for *locating* the pins. The real
 * tamper-resistance comes from aspin_bind_key() cryptographically binding the
 * pin to key material (see aspin.c and docs/HARDENING.md) — not from hiding it.
 */
#include "pins.h"

/* Symmetric secrets live in the binary by necessity (see HARDENING.md, "what
 * this does and does not buy you"). */
const uint8_t ASPIN_MASK_SECRET[ASPIN_SECRET_LEN] = {
    'a', 's', 'p', 'i', 'n', '/', 'm', 'a', 's', 'k', '/', 'v', '1'};
const uint8_t ASPIN_ROOT_SECRET[ASPIN_SECRET_LEN] = {
    'a', 's', 'p', 'i', 'n', '/', 'r', 'o', 'o', 't', '/', 'v', '1'};

/* Two masked pins (demo issuer public keys). Replace with your own and
 * regenerate with tools/gen_pins (see docs/HARDENING.md, "provisioning"). */
const uint8_t ASPIN_MASKED_PINS[ASPIN_PIN_COUNT][ASPIN_PIN_LEN] = {
    {/* masked pin[0] */
     0xad, 0x46, 0x53, 0xbc, 0xec, 0xe1, 0xab, 0xcb, 0xae, 0xd9, 0x66, 0xea,
     0xe7, 0x83, 0x86, 0x3d, 0xb3, 0xe7, 0x68, 0x0e, 0xa1, 0xdf, 0x5e, 0xe7,
     0x34, 0xf3, 0x2f, 0x0d, 0x37, 0xc5, 0x91, 0xb6},
    {/* masked pin[1] */
     0x5a, 0x7e, 0x4d, 0x9e, 0xf2, 0xb8, 0xb2, 0x94, 0x2b, 0x11, 0x58, 0xca,
     0x85, 0xac, 0x86, 0x1b, 0x45, 0xd8, 0xea, 0x28, 0x90, 0x3a, 0xad, 0x1d,
     0x0d, 0x7e, 0xcb, 0x49, 0xc4, 0x5a, 0xe2, 0x75},
};
