# identity

Hands-on identity & authentication mechanisms, each self-contained and
runnable on one machine (Python + Flask + SQLite). Built to *learn by diffing*:
every version is a full copy of the previous one plus a few clearly-scoped
security fixes, each documented with the **threat** it addresses.

## Mechanism 01 — Login + Password

A progressive hardening of email + password login into a protected web app.
Each directory has its own `README.md` with the threat model.

| Directory | Adds | Focus |
|-----------|------|-------|
| [`01-login-password`](01-login-password/) | baseline | Minimal, readable login: bcrypt-hashed passwords, signed-cookie session, protected dashboard |
| [`02-secrets-transport`](02-secrets-transport/) | 1–3 | **Secrets & transport:** secret key from env, debug off, TLS/HTTPS |
| [`03-auth-robustness`](03-auth-robustness/) | 4–6 | **Auth robustness:** hardened cookie flags, brute-force rate limiting, timing/enumeration fix |
| [`04-web-hardening`](04-web-hardening/) | 7–9 | **Web attack surface:** CSRF tokens, bcrypt 72-byte truncation fix, security headers |
| [`05-defense-in-depth`](05-defense-in-depth/) | 10–13 | **Defense in depth:** revocable server-side sessions, password policy, auth logging, error pages |

See exactly what each step changes:

```bash
diff -ru 01-login-password           02-secrets-transport
diff -ru 02-secrets-transport 03-auth-robustness
diff -ru 03-auth-robustness 04-web-hardening
diff -ru 04-web-hardening 05-defense-in-depth
```

### Quick start (any directory)

```bash
cd <directory>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# 02+ require a secret key:
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py
python app.py          # then open http://127.0.0.1:5000
```

Test accounts (from `seed.py`):
`alice@example.com` / `correct-horse-battery-staple` ·
`bob@example.com` / `hunter2`

## The 13 hardening items (mechanism 01)

1. Secret key from environment (no hard-coded key)
2. Debug server off by default
3. TLS / HTTPS
4. Hardened session cookie (`Secure`/`HttpOnly`/`SameSite`/expiry)
5. Brute-force / credential-stuffing rate limiting
6. Timing side-channel / user-enumeration fix
7. CSRF protection
8. bcrypt 72-byte truncation fix
9. Security response headers
10. Revocable server-side sessions ("log out everywhere")
11. Password policy (length + breached/common rejection)
12. Authentication logging (never logs passwords)
13. Custom error pages (no stack-trace leakage)

## Mechanism 06 — Machine / agent authentication

How a non-human client (script, service, autonomous agent) authenticates to an
API. JSON over `Authorization: Bearer` — no browser, cookie, or session.

| Directory | Focus |
|-----------|-------|
| [`06-api-keys`](06-api-keys/) | **API keys:** long-lived, hashed-at-rest, revocable per-key credentials sent on every request; per-client resource isolation |
| [`07-jwt`](07-jwt/) | **JWT:** exchange an API key at a token endpoint for a short-lived, signed, scoped token the API verifies statelessly (OAuth2 client-credentials) |
| [`08-token-lifecycle`](08-token-lifecycle/) | **Refresh + revocation + introspection:** revocable refresh tokens with rotation & reuse detection, a `jti` deny-list to kill access tokens before expiry, and an RFC 7662 `/introspect` endpoint |

Key idea carried into 06: an API key is 256 bits of randomness, so it's hashed
with **SHA-256 (fast)**, not bcrypt — slow hashing only helps low-entropy human
passwords. See `06-api-keys/README.md` for the full threat model.

## Mechanism 11 — mTLS (certificate-based machine identity)

The certificate counterpart to 06–08: instead of a bearer secret, the client
authenticates during the **TLS handshake** with an X.509 client certificate. No
`Authorization` header — identity lives in the transport.

| Directory | Focus |
|-----------|-------|
| [`11-mtls`](11-mtls/) | **Mutual TLS:** self-contained CA issues server + per-agent client certs; server requires a client cert (`CERT_REQUIRED`); identity = the verified cert's CN + fingerprint; fingerprint allow-list for revocation |
| [`12-cert-bound-tokens`](12-cert-bound-tokens/) | **Certificate-bound tokens (RFC 8705):** mTLS (11) + JWT (07) — the token carries `cnf.x5t#S256` (the client cert thumbprint); every call must present the matching cert, so a stolen token can't be replayed |
| [`13-dpop`](13-dpop/) | **DPoP (RFC 9449):** same sender-constraint as 12 but **without mTLS** — the client signs a per-request proof with its own key; the token carries `cnf.jkt` (the key thumbprint), so a stolen token is useless without the private key |

Unlike a bearer token, the client must hold the **private key**, so a leaked
request/log can't be replayed (11) — and 12 carries that guarantee up into the
token layer (sender-constrained tokens). See each subfolder's README for the
trade-offs.

## Mechanism 09–10 — Delegated access & federated identity (OAuth2 / OIDC)

How a user lets a *separate app* act for them **without sharing their password**
— "Log in with…" / "Connect your account". Browser redirect flow with user
login + consent.

| Directory | Focus |
|-----------|-------|
| [`09-oauth2-auth-code-pkce`](09-oauth2-auth-code-pkce/) | **OAuth2 Authorization Code + PKCE (authorization):** authorization server + resource server + demo client; user login (bcrypt) → consent → one-time code → PKCE token exchange → scoped JWT access token |
| [`10-openid-connect`](10-openid-connect/) | **OpenID Connect (authentication):** adds the `openid` scope, a signed **`id_token`**, `nonce`, **RS256 + JWKS** (asymmetric signing), discovery, and `/userinfo` — the "who is the user" layer on top of 09 |

Ties the series together: the user still authenticates with a **bcrypt password**
(mechanism 01), and 10 upgrades token signing from the shared-secret **HS256**
(07–09) to **asymmetric RS256** verified via JWKS. Both run in a browser or via
`client_example.py`.

| [`14-saml`](14-saml/) | **SAML 2.0 Web Browser SSO:** the enterprise sibling of OIDC — IdP + SP + demo; a signed XML **assertion** (XML-DSig, `signxml`) carries identity, verified against the IdP cert with audience/`InResponseTo`/conditions/replay checks |

## Next mechanisms (planned)
Signup + email verification + password reset · TOTP/2FA · WebAuthn/passkeys ·
mTLS · SAML.
Given the sibling `agent-auth-research` work, machine/agent credential flows
are the current focus.
