/*
 * Advanced SSL Pinning (aspin)
 * Tamper-resistant TLS certificate pinning for native (C/C++) libraries.
 *
 * Any library can compare a certificate against a pin. The hard part — and the
 * point of this one — is making that check survive a static binary patch. The
 * standard attack flips a single condition branch ("match? -> accept") or stubs
 * the verify function to `return true`. aspin removes that single point of
 * failure. See docs/HARDENING.md for the full rationale.
 *
 * Two modes:
 *   - aspin_verify_spki(): a classic boolean verdict. Branch-reduced and
 *     constant-time, but it still ends in one boolean — the very thing an
 *     attacker patches. Provided for comparison and low-risk paths.
 *   - aspin_bind_key(): the hard mode. It derives a key cryptographically BOUND
 *     to the presented certificate's public key and to this module's integrity.
 *     There is no accept/reject branch to flip: a wrong certificate (or a patched
 *     module) yields the wrong key, so whatever the app protects with that key —
 *     a sealed config, a request MAC, the session itself — simply stops working.
 */
#ifndef ASPIN_H
#define ASPIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASPIN_PIN_LEN 32    /* SHA-256 of the DER SubjectPublicKeyInfo */
#define ASPIN_KEY_LEN 32
#define ASPIN_DIGEST_LEN 32

typedef struct aspin_ctx aspin_ctx;

/* Create a context holding the obfuscated, compiled-in pin set.
 * Returns NULL on allocation failure. */
aspin_ctx *aspin_create(void);
void aspin_destroy(aspin_ctx *ctx);

/* SHA-256 pin of a DER SubjectPublicKeyInfo. */
void aspin_spki_pin(const uint8_t *spki, size_t spki_len,
                    uint8_t out[ASPIN_PIN_LEN]);

/*
 * WEAK (compat) mode. Returns 1 if the SPKI matches a pin, 0 otherwise.
 * The compare is constant-time and the loop has no early-exit, but the result is
 * still a single boolean an attacker can force. Prefer aspin_bind_key().
 */
int aspin_verify_spki(const aspin_ctx *ctx, const uint8_t *spki, size_t spki_len);

/*
 * HARD mode. Derive a 32-byte key bound to the presented SPKI and this module's
 * integrity. The key equals the key the server used at provisioning ONLY when the
 * SPKI matches a pin AND the module is unpatched. There is no verdict branch.
 *
 * Returns 0 on success (a key is always produced — correctness is proven by
 * whether the key then works), or -1 on bad arguments.
 */
int aspin_bind_key(const aspin_ctx *ctx, const uint8_t *spki, size_t spki_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t out_key[ASPIN_KEY_LEN]);

/*
 * Module integrity digest folded into aspin_bind_key: it covers the obfuscated
 * pin table, the masks and the embedded secrets, so patching any of them changes
 * every derived key. Exposed for diagnostics and tests.
 */
void aspin_self_digest(const aspin_ctx *ctx, uint8_t out[ASPIN_DIGEST_LEN]);

/*
 * Utility: SHA-256 over `len` bytes of code starting at `fn` (e.g. a verify
 * routine). Folding this into key derivation makes a patch to that code change
 * the key — full "text integrity". It is platform-specific (some targets map
 * code execute-only), so the default build folds in data integrity only; see
 * docs/HARDENING.md for wiring it into production via linker section bounds.
 */
void aspin_text_checksum(const void *fn, size_t len, uint8_t out[ASPIN_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ASPIN_H */
