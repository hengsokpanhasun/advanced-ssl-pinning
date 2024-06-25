# Hardening notes — making certificate pinning hard to patch

Certificate pinning is easy to *write* and, in most apps, easy to *defeat*. An
analyst with the binary rarely attacks the crypto — they attack the one place the
code turns the result into an **accept/reject decision**, and flip it. This
document catalogs the standard attacks and the specific choices in this library
that blunt each one.

The guiding principle: **never let the trust decision be a single boolean.** If
there is one branch, one return value, or one comparison that means "trusted", a
patch of a few bytes defeats the whole scheme. Bind the certificate to something
the app *needs* instead.

---

## Attack 1 — Flip the verdict branch

The most common patch. The check compiles to something like:

```asm
    bl   verify_chain
    cmp  w0, #1
    b.ne reject          ; <- flip this one instruction
    ... continue (trusted) ...
reject:
    ... throw / close connection ...
```

Flipping `b.ne` → `b.eq` (a single condition-bit change) inverts accept and
reject. The same trick works on `cbnz`↔`cbz` guarding a pin-match loop.

**Defense here.** Hard mode (`aspin_bind_key`) has **no verdict branch at all**.
It computes

```
key = HMAC(master, SHA256(presented_pin ‖ self_digest ‖ info))
```

and returns the key unconditionally. Nothing is compared to decide "trusted".
There is no `b.ne` to invert because there is no branch — the certificate's public
key is an *input to a key derivation*, not an operand of a comparison.

## Attack 2 — Stub the verify function to `return true`

Overwrite the first instructions of the verify routine with `mov w0, #1 ; ret`.
Now every certificate "verifies".

**Defense here.** There is no function that returns "verified". `aspin_bind_key`
returns 32 bytes of key material; forcing it to return a constant just makes it
return a *constant wrong key*, which fails to unseal the provisioned data. The
weak boolean `aspin_verify_spki` can of course be stubbed — which is precisely why
it is documented as the weak path and the demo shows the hard path instead.

## Attack 3 — Anchor on the error string

Pinning code usually builds a message like `"Pinning validation failed."`. That
string has exactly one cross-reference, and it points straight at the check. Find
the string, find the branch, flip it (Attack 1).

**Defense here.** The hard path emits **no strings** near the decision — there is
no decision and no error message to anchor on. Keep user-facing pinning errors
(if any) far from the comparison, behind generic/opaque codes, so a `strings`
sweep does not map out the check for the attacker.

## Attack 4 — Scan or diff for the pin table

Pins are often a plaintext array of 32-byte SHA-256 hashes in `.rodata`. An
analyst greps for the table, or diffs the app against a public pin set, to locate
and neutralize the comparison — or simply swaps in their own pin.

**Defense here.** Pins are stored XOR-masked (`src/pins.c`):
`stored[i] = pin[i] ^ SHA256(secret ‖ i)`. No 32-byte pin appears in the binary;
the plaintext exists only briefly in RAM inside `aspin_create`. More importantly,
the pins are folded into `master` and `self_digest`, so **swapping a pin changes
every derived key** — an attacker who substitutes their own pin breaks the app
rather than bypassing it.

## Attack 5 — Patch the comparison or the pins anyway

Even with the above, an attacker can still flip bytes and see what happens.

**Defense here — self-integrity.** `aspin_bind_key` folds `self_digest` (a hash
over the obfuscated pin table, the masks and the embedded secrets) into every key.
Patch any of those bytes and the key changes. `aspin_text_checksum` extends the
same idea to a span of code: hash the derive routine and fold it in, so patching
the *logic* also changes the key. (Text integrity is platform-specific — some
targets map code execute-only — so the default build folds data integrity only;
see "Text integrity in production" below.)

## Attack 6 — Trust the system / user CA store, or inject a network config

On the platform side, many MITM setups just add a CA to the trust store, or edit
an app's network-security configuration to trust user CAs.

**Defense here.** Pinning by key-binding never consults the system trust store:
the derived key is correct only for the *specific* provisioned public key, so a
new CA in the store is irrelevant. This mirrors how the strongest production
stacks pin — against their own key material, with the pin bound into the
connection — rather than against the OS trust decision.

---

## Proof of possession — why this is the strong form

The pattern in hard mode is **proof of possession**: the server (or your
provisioning step) seals something the client needs — a config blob, an API
token, a session key — under a key derived from the server's real public key. The
client re-derives that key from the public key presented during the TLS
handshake. If it's the real key, the seal opens; if it's a MITM key, it doesn't.

The attacker cannot produce the real server's private key, and there is no branch
to patch, so the only ways through are to obtain the genuine certificate (they
can't) or to extract the already-unsealed secret from a running, instrumented
device — a far higher bar than a two-byte static patch, and one that moves the
fight to runtime (anti-debug, attestation) where you want it.

## Provisioning (generating your own pins)

```sh
# 1. Extract the DER SubjectPublicKeyInfo of your server/issuer cert
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der > spki.der

# 2. Produce the obfuscated row and paste it into src/pins.c (index 0, 1, ...)
./build/gen_pins 0 spki.der
```

Pin the **issuer or intermediate** public key, not just the leaf, so certificate
rotation doesn't brick clients. Keep at least one backup pin.

## Text integrity in production

The portable default folds **data** integrity (pins + secrets) into the key. To
also bind the **code**, checksum the derive routine and fold it into provisioning:

- GCC/Clang/ELF: bracket the routine with linker section symbols
  (`__start_<section>` / `__stop_<section>`) and hash between them.
- Mach-O: use `getsectiondata` for a dedicated `__TEXT` section.
- MSVC/PE: use a named section and the `$start`/`$end` segment markers.

Then the provisioned key is derived with that checksum included, and any patch to
the routine changes the key — closing Attack 5 completely.

## What this does and does not buy you

- **Does:** remove the single-branch/`return true`/string-anchor/pin-swap patch
  targets; make a patch *self-defeating* (wrong key); keep trust independent of
  the OS CA store.
- **Does not:** defeat a determined runtime attacker who dumps the unsealed secret
  from memory on a rooted/jailbroken device, or who lifts the symmetric secrets
  from the binary. Obfuscation raises the cost of the former; pair this library
  with runtime defenses (root/debugger/hook detection, attestation) for the
  latter. Honesty about this boundary is part of the design.
