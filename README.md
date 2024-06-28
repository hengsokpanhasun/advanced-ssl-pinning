# Advanced SSL Pinning

Tamper-resistant TLS certificate pinning for native (C/C++) libraries.

Any library can compare a certificate against a pin. The hard part — and the whole
point of this one — is making that check **survive a static binary patch**. The
usual attack never touches the crypto: it finds the one place the code decides
"trusted vs not" and flips it (one condition branch, or a `return true` stub).
This library removes that single point of failure.

> C99 · no external dependencies (bundled SHA-256 / HMAC-SHA256) · CMake + CTest · MIT

## The idea in one line

Don't make the trust decision a boolean an attacker can flip — **bind the pinned
public key into key material the app actually needs**, so a wrong certificate (or
a patched module) yields the wrong key and the app simply stops working.

```c
#include "aspin.h"

aspin_ctx *ctx = aspin_create();

/* Weak, compat mode — a boolean verdict (patchable at the call site). */
int ok = aspin_verify_spki(ctx, spki_der, spki_len);

/* Hard mode — no verdict branch. The key is correct only for the pinned key. */
uint8_t key[ASPIN_KEY_LEN];
aspin_bind_key(ctx, spki_der, spki_len, (const uint8_t *)"session", 7, key);
/* ...use `key` to unseal a provisioned config / compute the request MAC / derive
   the session key. If the cert was a MITM cert, `key` is wrong and that fails. */

aspin_destroy(ctx);
```

## Why it resists patching

| Standard attack | What this does instead |
|-----------------|------------------------|
| Flip the accept/reject branch (`b.ne`↔`b.eq`, `cbnz`↔`cbz`) | Hard mode has **no branch** — the key derivation takes the public key as input |
| Stub verify to `return true` | No "verified" return exists; a forced constant is just a wrong key |
| Anchor on the `"Pinning validation failed."` string | No strings at the decision point |
| Grep / diff the plaintext 32-byte pin table | Pins stored **XOR-masked**; plaintext only in RAM |
| Swap in the attacker's own pin | Pins folded into the derived key → a swap **breaks** the app |
| Patch the pin or comparison bytes | A self-integrity digest (data, + optional code) is folded into every key |
| Add a CA to the trust store | Key-binding never consults the OS trust decision |

Full write-up: **[docs/HARDENING.md](docs/HARDENING.md)**. Scope and limits:
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

## Build, test, run

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure   # SHA/HMAC KATs + pinning behaviour
./build/aspin_demo                            # narrated walk-through
```

The demo shows the real cert unsealing a provisioned config while a MITM cert gets
unrecoverable garbage — with no branch in between to flip.

## API

| | |
|---|---|
| `aspin_create` / `aspin_destroy` | hold the obfuscated, compiled-in pin set |
| `aspin_spki_pin` | SHA-256 pin of a DER SubjectPublicKeyInfo |
| `aspin_verify_spki` | weak boolean verdict (constant-time, no early-exit) |
| `aspin_bind_key` | **hard mode** — key bound to the cert + module integrity |
| `aspin_self_digest` / `aspin_text_checksum` | integrity surfaces folded into the key |

## Your own pins

```sh
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der > spki.der
./build/gen_pins 0 spki.der    # paste the row into src/pins.c
```

Pin the **issuer/intermediate** key and keep a backup pin so certificate rotation
doesn't brick clients.

## Layout

```
include/aspin.h     public API
src/aspin.c         core: pinset, constant-time verify, key-binding, integrity
src/pins.c          obfuscated (XOR-masked) compiled-in pin set
src/sha256.*        bundled SHA-256 (FIPS 180-4)
src/hmac_sha256.*   bundled HMAC-SHA256 (RFC 2104)
examples/demo.c     narrated demo
tools/gen_pins.c    turn a DER SPKI into an obfuscated pin row
tests/              SHA/HMAC known-answer tests + pinning behaviour
docs/               hardening notes + threat model
```

## Scope & ethics

This is a **defensive** security-engineering project: it helps app developers make
their own certificate pinning resilient to tampering (OWASP MASVS resilience). It
is not an evasion tool, and it is honest about its ceiling — a determined runtime
attacker on a fully controlled device is out of scope (see the threat model). Pair
it with runtime defenses (root/debugger/hook detection, attestation).

## License

MIT © 2024 Sun Hengsokpanha
