# Security review — hand-rolled cryptographic verification

**Date:** 2026-08-02 · **Reviewer:** Claude (Opus 4.8), manual code-level review ·
**Verdict:** no exploitable vulnerabilities found in the code reviewed.

This is a point-in-time assurance record for the deepest-risk surface of the
repo — the **hand-rolled security verifiers**, where a subtle bug would be a real
authentication/authorization bypass (not caught by a happy-path test). It
complements the automated gate in [SECURITY.md](SECURITY.md) (the `test.py`
security-negatives, now run in CI).

> **Scope note.** This reviews *correctness of the security checks* in the modules
> listed below. It does not re-audit the intentional `/vuln/*` teaching foils
> (those are exploitable by design and contained to localhost — see
> [SECURITY.md](SECURITY.md)), nor deployment posture (a localhost teaching repo).

---

## Method

Each module was read line by line against the relevant spec, checking for the
classic bypasses: algorithm confusion / `alg:none`, signature-wrapping, missing
audience/issuer/expiry, non-constant-time secret comparison, replay, credential
substitution / identity read from an unverified artifact, and missing binding
between a token and its holder. The full `run-tests.sh` suite (30/30) was green
at review time.

---

## Verdict by module — critical checks present & correct

| Module | Verified correct |
|--------|------------------|
| **WebAuthn** `17/webauthn.py`, `17/app.py` | challenge match; **exact origin** match; `rpIdHash == SHA-256(rp_id)`; ECDSA-P256 signature over `authData‖SHA-256(clientData)`; strict-increasing sign counter (clone detection); **credential bound to the session user** (`app.py:117`); challenge held server-side between begin/finish |
| **TOTP** `16/totp.py` | RFC 4226 dynamic truncation correct; **constant-time** compare (`hmac.compare_digest`) per candidate; bounded ±1 skew window; numeric-input validation |
| **DPoP** `13/dpop.py`, `31/dpop.py` | `alg` pinned to ES256 on **both** the header check and `jwt.decode`; **rejects private keys** (`"d" in jwk`); `htm`/`htu`/`iat`-freshness/`jti`-replay/`ath` all checked; thumbprint is derived from the **same** JWK that verified the signature |
| **PKCE** `09/oauth.py` | `secrets.compare_digest` (constant-time); **S256 enforced** at `/authorize` (plain branch unreachable via the flow); one-time SHA-256-hashed auth codes bound to client + redirect_uri |
| **private_key_jwt** `30/clientauth.py` (also 31/32) | **audience-bound** (`audience=accepted_auds`); `alg` pinned RS256; `require exp/aud/jti`; RFC 7523 **`iss == sub == client_id`**; `jti` single-use; verified against the **registered** public key |
| **Agent access token** `30/tokens.py` | RS256 signature via JWKS public key; `alg` pinned; **audience-bound**; issuer checked; `require exp/aud/iss` |
| **SAML** `14/saml.py` | XSW-safe: verify then read identity **only** from `.signed_xml`; **pins the known IdP cert** (`x509_cert=idp_cert_pem`), not a message-embedded one; `InResponseTo`/Recipient/Conditions/Audience/replay all read from the signed element |
| **mTLS** `11/app.py` | `CERT_REQUIRED` + `load_verify_locations(ca.crt)` → peer cert TLS-verified before Flask; identity bound by **SHA-256 fingerprint** to a registered, non-revoked client |
| **Cert-bound token** `12/app.py` | **binding check** `token.cnf["x5t#S256"] == thumbprint(cert on this connection)` (`app.py:125`); an unbound token (`cnf` absent → `None`) is rejected |
| **SPIFFE** `15/spiffe.py`, `15/app.py` | X.509-SVID chain-verified to the bundle CA before the SPIFFE ID is read from the **URI SAN**; JWT-SVID `alg`-pinned, verified against the bundle JWKS by `kid`, `aud == server SPIFFE ID`; authorization is a **SPIFFE-ID allow-list** (rogue-but-valid SVID → 403) |
| **Token lifecycle** `08/db.py`, `08/app.py` | refresh **rotation** + **reuse detection** (revoked token replay → whole family revoked) + `jti` deny-list checked on every request |
| **REST authz** `27/authz.py` | response **public-field allow-list** serializer; **writable-field allow-list** narrower than the DB columns (blocks mass assignment); object-ownership and role checks in the `/safe` handlers (asserted by `test.py`) |

**The recurring strengths** that prevent the classic bypasses: algorithm pinning
everywhere (`algorithms=[…]` on every verify), constant-time comparison of every
secret/code, and identity always read from the *verified* artifact (`signed_xml`,
the TLS-verified peer cert, the session-bound credential, the same JWK that
checked the signature).

---

## Minor observations — non-exploitable

None rises to a finding. Listed for completeness; recommended tidy-ups marked ⚑.

| # | Module | Observation | Status |
|---|--------|-------------|--------|
| 1 | ⚑ WebAuthn `17/app.py` | `auth_challenge` / `reg_challenge` are popped from the session only on **success**, not on a failed ceremony. Not exploitable (a challenge is useless without the private key), but popping on failure is tidier. | recommended |
| 2 | ⚑ DPoP `13/dpop.py`, `31/dpop.py` | `crv` isn't explicitly pinned to `P-256`. Not exploitable — a wrong-curve key yields a different `jkt`, so the token-binding check fails — but asserting `jwk["crv"] == "P-256"` is stricter. | recommended |
| 3 | TOTP `16/totp.py` | no intra-step reuse rejection (a code is valid for its whole ±1 window). | already documented in `16/README.md` |
| 4 | WebAuthn `17/app.py` | registration isn't gated behind an authenticated session and doesn't require the UV flag. | by design (passwordless demo); documented in `17/README.md` |
| 5 | SAML `14/saml.py` | exact time comparisons, no clock-skew allowance, strict timestamp format. | documented in `14/README.md` |
| 6 | SPIFFE `15/spiffe.py` | `verify_jwt_svid` doesn't `require` `exp` (PyJWT enforces `exp` when present but doesn't require its presence). Not exploitable (forging needs the bundle key). | recommended, low value |
| 7 | Token lifecycle `08/db.py` | refresh rotation isn't atomic across the per-call SQLite connections (a concurrent double-refresh race). | single-process demo; production note in `08/README.md` |

---

## Coverage

**Reviewed:** 08, 09, 11, 12, 13, 14, 15, 16, 17, 27, 30 (and the shared DPoP /
`private_key_jwt` code reused by 31/32).

**Not individually re-read** (lower risk — same primitives, or non-crypto):
18 (SCIM is a directory-state store, not an access gate), 19/24/26 (reuse 09/10's
reviewed OAuth core), 20–23 (structural, not cryptographic — the `/vuln`-vs-`/safe`
contrast is asserted by their tests), 25 (single-use hashed token, same pattern as
06/08).

## Recommendation

The reviewed code is sound; ship as-is. The two ⚑ tidy-ups (observations 1 and 2)
are optional hygiene, not fixes — apply them if/when convenient. Re-run this
review when a mechanism's verifier changes, and keep the CI suite green as the
first line of defense (see [SECURITY.md](SECURITY.md)).
