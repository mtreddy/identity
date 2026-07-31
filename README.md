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

## Tests

Every mechanism has a self-contained `test.py` asserting both its happy path and
the security-negative checks (e.g. PKCE wrong-verifier, id_token
nonce/audience/`alg:none` rejection, TOTP RFC-6238 vectors, mTLS untrusted-CA
refusal, cert-bound/DPoP replay, SAML tamper/replay, the SQLi exploits). Run one,
or all:

```bash
./run-tests.sh                 # every mechanism, each in its own venv
./run-tests.sh 09-* 16-totp    # only the named directories

# or a single mechanism directly (inside its venv):
cd 10-openid-connect && python test.py
```

Each `test.py` starts the app, runs its checks, prints PASS/FAIL, and exits
nonzero on any failure. The shared harness is `testlib.py`. All 29 pass.

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

### Second factor & passwordless

| Directory | Focus |
|-----------|-------|
| [`16-totp`](16-totp/) | **TOTP two-factor (RFC 6238):** password (factor 1) + a 6-digit time-based code from an authenticator app (factor 2); HOTP/TOTP implemented from the standard library, with enrollment, ±1-step skew, rate limiting |
| [`17-webauthn`](17-webauthn/) | **WebAuthn / passkeys:** phishing-resistant public-key login — the device signs a challenge bound to the origin; server stores only public keys. Ceremonies + signature verification hand-rolled, with a software authenticator for headless runs and a browser page |

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
| [`15-spiffe`](15-spiffe/) | **SPIFFE / SVID:** workload identity — a SPIFFE ID (`spiffe://…`) in an X.509 URI SAN (**X.509-SVID**, workload mTLS) or a **JWT-SVID**, verified against a trust bundle and authorized by a SPIFFE-ID policy |

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
| [`19-sso-mailbox`](19-sso-mailbox/) | **"Sign in with SSO, then read your mailbox":** a concrete authenticate→authorize→access-a-resource demo on OIDC — a third-party app gets `mail:read` consent and reads a mock inbox; the scope is enforced at the resource (a token without `mail:read` gets 403) |
| [`24-device-grant`](24-device-grant/) | **OAuth2 Device Authorization Grant (RFC 8628):** login for input-constrained devices (TV/CLI/IoT) — the device shows a `user_code` + URL, the user approves in a phone browser, the device polls `/token` through the `authorization_pending` / `slow_down` / `access_denied` / `expired_token` state machine to a token |

Ties the series together: the user still authenticates with a **bcrypt password**
(mechanism 01), and 10 upgrades token signing from the shared-secret **HS256**
(07–09) to **asymmetric RS256** verified via JWKS. Both run in a browser or via
`client_example.py`.

| [`14-saml`](14-saml/) | **SAML 2.0 Web Browser SSO:** the enterprise sibling of OIDC — IdP + SP + demo; a signed XML **assertion** (XML-DSig, `signxml`) carries identity, verified against the IdP cert with audience/`InResponseTo`/conditions/replay checks |
| [`18-scim`](18-scim/) | **SCIM 2.0 provisioning:** the lifecycle layer for SSO — a bearer-authed REST API (`/scim/v2`) where an IdP creates, updates, **deactivates**, and deletes Users/Groups (CRUD + PATCH + filter + pagination), keeping the app's directory in sync as people join and leave |

## Agent ↔ model authentication

How an **AI agent calls a remote (or local) model/tool** securely — token-mediated
access with the model endpoint as an OAuth 2.1 Resource Server, and the agent
verifying the endpoint in return. Design record: [AGENT_MODEL_AUTH.md](AGENT_MODEL_AUTH.md).

| Directory | Focus |
|-----------|-------|
| [`30-agent-model-oauth`](30-agent-model-oauth/) | **Agent → model over OAuth:** the model gateway is a Resource Server; the agent authenticates with **`private_key_jwt`** (RFC 7523) or `client_secret` and gets a **short-lived, audience-bound (RFC 8707/9728), scoped** token; the gateway enforces `aud` + scope + a per-client model allow-list. `/vuln` shows the static-API-key anti-pattern it replaces |
| [`31-agent-model-dpop`](31-agent-model-dpop/) | **Sender-constrained model token (DPoP, RFC 9449):** 30's token, made unstealable — bound to the agent's key via `cnf.jkt`, with a fresh DPoP proof on every call. A **stolen token is inert** on `/v1` but replays on the `/vuln` bearer path. Builds on `13-dpop` |
| [`32-agent-obo`](32-agent-obo/) | **Agent → model on-behalf-of a user (token exchange, RFC 8693):** the agent exchanges the user's token for a **downscoped** access token (`sub`=user, `act`=agent) whose authority is the *user ∩ agent* intersection — it **can never exceed the user it serves**. `/v1` requires the OBO token; `/vuln` shows the confused deputy where the agent's own token reaches a model the user may not use |

## Application security foundations

Cross-cutting web-security topics that underpin the mechanisms above.

| Directory | Focus |
|-----------|-------|
| [`20-sql-injection`](20-sql-injection/) | **SQL injection defense:** vulnerable vs. safe queries side by side; real exploits (auth bypass, tautology, UNION exfiltration, ORDER BY injection) that fall on `/vuln/*` and hold on `/safe/*`. Primary fix: **parameterized queries**; plus identifier allow-lists, least privilege, the driver stacked-query caveat |
| [`21-csrf`](21-csrf/) | **CSRF attack vs. defense:** an attacker page auto-submits a cross-site form; the forged request takes over the account on the unprotected endpoint and is blocked (403) on the token-protected one. Shows the **synchronizer token**, **`SameSite` cookie**, and OAuth **`state`** defenses |
| [`22-xss`](22-xss/) | **XSS attack vs. defense:** reflected + stored + DOM payloads; the same `<script>` reflects raw (would execute) on `/vuln` and is encoded to inert text on `/safe`. Shows **output encoding** (Jinja autoescaping), **Content-Security-Policy**, and **`HttpOnly`** cookies |
| [`23-cors-spa`](23-cors-spa/) | **CORS + browser SPA:** a real two-origin setup (SPA on one port, API on another); correct **preflight** + origin **allow-list** + credentials vs. the reflect-any-origin **misconfiguration**. Teaches that **CORS relaxes the same-origin policy — it is not a defense** |
| [`27-rest-api-authz`](27-rest-api-authz/) | **REST API authorization:** the bugs authentication doesn't fix — **BOLA/IDOR**, **BFLA**, **mass assignment**, and **excessive data exposure** (OWASP API1/3/5/6) as `/vuln` vs `/safe` pairs. Every request is authenticated; the fix is object-, function-, and field-level checks at the endpoint + a response allow-list |

## Provisioning & bootstrap

Where the identities and secrets *come from* before first use — the deliberate
counterpart to the ad-hoc `seed.py` init in every other directory. See
[PROVISIONING.md](PROVISIONING.md) for the full per-mechanism, per-layer story
(users, clients, server secrets/keys/certs).

| Directory | Focus |
|-----------|-------|
| [`25-signup-verification`](25-signup-verification/) | **Self-service user provisioning:** signup gated by **email verification** — a single-use, short-TTL, hashed token proves control of the address before the account can log in; no account-enumeration oracle. The *Users* front door (builds on `05`) |
| [`26-dynamic-client-registration`](26-dynamic-client-registration/) | **OAuth2 Dynamic Client Registration (RFC 7591/7592):** clients register themselves at `/register` (gated by an initial access token) and manage themselves with a per-client registration access token; hard **redirect-URI validation** and **scope clamping**. The *Clients* front door (builds on `09`) |

**`bootstrap.py`** — a one-command provisioning step for the *server-held*
secrets each mechanism reads from the environment (`SECRET_KEY`, `JWT_SECRET`,
`REGISTRATION_TOKEN`, …), generating strong values into a gitignored
`<dir>/.dev-secrets.env` instead of you inventing them by hand:

```bash
python bootstrap.py list          # what each mechanism needs
python bootstrap.py 26            # provision one (prefix is enough)
python bootstrap.py --all         # provision every mechanism
```

## Next mechanisms (planned)
See [TODO.md](TODO.md) for the backlog — next up are **magic-link / email OTP**
and **admin/invite-based** user provisioning, plus enhancements to existing
mechanisms.
