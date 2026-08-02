# The algorithms underneath, and how their hardness helps

Every mechanism in this repo rests on a cryptographic (or structural) primitive.
This document is the cross-cutting answer to **"what algorithm is actually doing
the work, and *why* is it secure?"** — mapping each mechanism to the hard problem
it depends on, with the exact primitives and parameters the code uses.

Companion to [PATTERNS.md](PATTERNS.md) (design patterns), [TRUST.md](TRUST.md)
(root of trust), and [PROVISIONING.md](PROVISIONING.md).

> **The organizing idea.** Under all 30 mechanisms sit just **six hardness
> assumptions**. The recurring design skill is **matching the right hardness to
> the threat and to the entropy of what you're protecting** — most visibly in the
> choice of a *slow* hash for passwords vs. a *fast* one for keys.

---

## The six hardness families

| # | Hardness assumption | Primitive(s) in this repo | What "hard" buys you |
|---|---------------------|---------------------------|----------------------|
| 1 | **Search-space size** (information-theoretic) | CSPRNG — `secrets.token_*` (OS entropy) | can't guess a 256-bit value: 2²⁵⁶ tries |
| 2 | **One-wayness / preimage resistance** | SHA-256 | given `H(x)`, can't recover `x`; can't find a colliding `x` |
| 3 | **Economic cost** (deliberately slow KDF) | bcrypt (cost 12, salted) | each brute-force guess is expensive |
| 4 | **MAC unforgeability** (PRF) | HMAC-SHA1 (cookies/CSRF/TOTP), HMAC-SHA256 (HS256) | can't forge a tag without the key |
| 5 | **Trapdoor** (factoring / discrete log) | RSA-2048 (RS256, X.509, XML-DSig), ECDSA P-256 (ES256) | verify without being able to mint |
| 6 | **Key-exchange + AEAD** | ECDHE + AES-GCM (TLS), mTLS | private channel with forward secrecy |

---

## 1 · Search-space hardness — CSPRNG

The "algorithm" is just an OS CSPRNG (`secrets`); security is purely the **size of
the space**, no math trapdoor. Exact widths in the code:

| Width | Call | Used for |
|-------|------|----------|
| **256-bit** | `token_urlsafe(32)` / `token_hex(32)` | API keys (06), refresh tokens (08), device codes (24), email-verification tokens (25), SCIM token (18), PKCE verifier (09), `SECRET_KEY` / `JWT_SECRET` |
| **192-bit** | `token_urlsafe(24)` | client secrets `cs_…` + registration access tokens (26, 30–32) |
| **160-bit** | `token_bytes(20)` → Base32 | TOTP shared secret (16) |
| **128-bit** | `token_urlsafe(16)` | JWT `jti` replay ids (30–32) |

**Why it matters:** a 256-bit key **cannot be brute-forced at any hash speed**, so
it needs a *fast* hash (family 2), never bcrypt — the reasoning spelled out in
`06`'s README.

## 2 · One-wayness — SHA-256

Two uses, each leaning on a different property:

- **Store the proof, not the secret** (preimage resistance): API keys (06),
  refresh tokens (08), SCIM / registration / verification tokens (18/25/26) are
  stored as `sha256(secret)`. A DB leak yields hashes you can't reverse.
- **Binding** (second-preimage / collision resistance): the mTLS cert
  **fingerprint** (11), the cert-bound **`x5t#S256`** thumbprint (12), the DPoP
  **`jkt`** (RFC 7638 JWK thumbprint, 13/31), the DPoP **`ath`** =
  `sha256(access_token)`, and **PKCE `S256`** = `sha256(verifier)` (09). Hardness
  here means no attacker can find a *different* cert/key/verifier with the same
  digest — the binding can't be spoofed.

## 3 · Economic hardness — bcrypt

Passwords are **low-entropy and human-chosen**, so the search space (family 1) is
*small*; hardness must be **added** via a tunable work factor. bcrypt (`gensalt()`
→ cost 12, per-password random salt) makes each guess ~expensive and defeats
rainbow-table precomputation. Used in **01–05, 16**.

- **05's refinement:** `sha256(password)` → base64 (fixed 44 bytes) *then* bcrypt,
  so the whole password contributes entropy despite bcrypt's 72-byte input cap.
- **The master trade-off** (stated in `06`): *match KDF speed to entropy.* Slow
  (bcrypt) for low-entropy passwords; fast (SHA-256) for high-entropy keys.
  bcrypt on a 256-bit key wastes CPU for zero gain; SHA-256 on a password is
  catastrophic (GPU brute-force).

## 4 · MAC unforgeability — HMAC

| Where | Primitive |
|-------|-----------|
| Session cookie signing (`SECRET_KEY`, itsdangerous) | HMAC-SHA1 — 01–05, 09, 10, 19 |
| CSRF token (`payload.timestamp.signature`) | HMAC-SHA1 — 04, 21 |
| HS256 JWTs | HMAC-SHA256 — 07, 08, 09, 13 (access token), 24, 26 |
| HOTP/TOTP over a time counter | HMAC-SHA1 — 16 (RFC 4226/6238) |

Security is **existential unforgeability**: no valid tag without the key. Two
nuances: (a) **HMAC-SHA1 is still secure** even though SHA-1's *collision*
resistance is broken — HMAC rests on PRF/MAC properties, not collision
resistance. (b) HMAC is **symmetric**: whoever can *verify* can also *mint* — the
single limitation that pushes the repo to family 5 at OIDC.

## 5 · Trapdoor hardness — RSA & ECDSA

The biggest structural leap: **verify-without-mint**, resting on integer
factorization (RSA) and the elliptic-curve discrete-log problem (ECDSA).

| Primitive | Parameters | Used for |
|-----------|-----------|----------|
| **RSA / RS256** | 2048-bit, `e=65537`, SHA-256 | id/access tokens + JWKS (10, 19, 30–32), `private_key_jwt` assertions (30–32), X.509 CA/cert signatures (11, 12, 15), SAML XML-DSig (14) |
| **ECDSA / ES256** | curve `SECP256R1` (P-256), SHA-256 | DPoP proofs (13, 31), WebAuthn assertions (17) |

**Why the hardness helps:** the public key can't yield the private key, so (a)
many independent verifiers can check a token while only the issuer can mint it
(federation, agents), and (b) **proof-of-possession** works — signing a fresh
challenge (WebAuthn) or per-request proof (DPoP) proves you hold the key without
revealing it. P-256 and RSA-2048 both target ~128-bit security; EC is chosen
where per-request signing speed/size matters.

## 6 · Channel hardness — TLS / mTLS

Everything runs over TLS: **ECDHE** key agreement (computational Diffie-Hellman →
forward secrecy) + **AES-GCM** AEAD (confidentiality + integrity). mTLS (11/12)
reuses the cert signatures of family 5 for *mutual* authentication in the
handshake itself.

---

## Cross-cutting themes

### Hardness is necessary but not sufficient — prevent downgrade
Every JWT verify **pins** `algorithms=[…]` (`HS256`/`RS256`/`ES256`), because
`alg:none` and HS/RS-confusion attacks **bypass the hard problem by swapping the
algorithm**, not by solving it. The repo never trusts the token's own `alg`
header (07, 10, 13, 30 all call this out). Same spirit: SAML reads identity only
from the element the signature actually covers (14, XML-signature-wrapping).

### Not every guarantee is cryptographic
`20` (SQLi), `22` (XSS), `23` (CORS), `27` (authz) rely on **structural**
guarantees, not hardness: prepared statements *categorically* separate code from
data (a stronger, non-probabilistic guarantee than any hash); output encoding;
policy checks. A parser guarantee beats a hardness assumption when you can get
one.

### A consistent ~128-bit floor, and a quantum horizon
RSA-2048, P-256, SHA-256, and 256-bit tokens all target ~128-bit work. The
**asymmetric** layer (family 5, factoring/ECDLP) falls to Shor's algorithm; the
symmetric/hash layers (families 2, 4, 6 — AES, SHA-256, HMAC) are only *halved*
by Grover's. So post-quantum migration is a problem for **RSA/ECDSA specifically**
— the future frontier for the token, certificate, and passkey families.

---

## Per-family quick index

- **Guess-resistance:** every high-entropy secret — 06, 08, 09, 16, 18, 24, 25, 26, 30–32.
- **One-wayness/binding:** 06, 08, 09 (PKCE), 11, 12, 13, 18, 25, 26, 31.
- **Slow KDF:** 01–05, 16.
- **HMAC:** 01–05 (cookie), 04/21 (CSRF), 07/08/09/13/24/26 (HS256), 16 (TOTP).
- **Asymmetric:** 10, 11, 12, 13, 14, 15, 17, 19, 30, 31, 32.
- **Channel/TLS:** all; **mutual** at 11, 12.
- **Structural (non-crypto):** 20, 22, 23, 27.
