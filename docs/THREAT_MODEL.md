# Threat model

## Who we defend against

A capable analyst with the shipped native binary and a MITM proxy, who wants to
read or modify the app's TLS traffic. Their cheapest tools are **static binary
patching** (flip a branch, stub a function) and **trust-store / network-config
manipulation**. This library is built to make those cheap attacks fail.

## In scope

| Attack | Mitigation |
|--------|------------|
| Flip the accept/reject branch | Hard mode has no verdict branch (`aspin_bind_key`) |
| Stub verify to `return true` | No "verified" return; a forced constant is a wrong key |
| Anchor on the pinning error string | No strings at the decision point |
| Grep / diff the plaintext pin table | Pins stored XOR-masked; folded into the key |
| Swap in an attacker's pin | Pins bound into `master` → swap breaks the app |
| Patch the comparison or pin bytes | `self_digest` (data) + optional text checksum folded into the key |
| Add a CA to the trust store | Key-binding ignores the OS trust decision |

## Out of scope (pair with other controls)

- **Runtime memory extraction** on a rooted/jailbroken, instrumented device
  (Frida/debugger dumping the unsealed secret or the derived key). Mitigate with
  anti-debug, hook detection, and attestation — not with this library alone.
- **Lifting the symmetric secrets** compiled into the binary. They are obfuscated
  and split, which raises cost, but a symmetric secret in a client binary is
  recoverable in principle. The key-binding still prevents a *static* bypass.
- **Compromise of the real private key / a mis-issued certificate** by a trusted
  CA. That is a PKI problem; pin the issuer and keep backup pins.
- **TLS library bugs** (downgrade, parsing). Keep your TLS stack current.

## Residual risk

The honest ceiling is a runtime attacker on a fully controlled device. The design
goal is to move the fight off the trivially-cheap static-patch plane and onto that
plane, where defenders have real tools (attestation, integrity, detection) — not
to claim an unbreakable client.
