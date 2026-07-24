# TODO — future mechanisms & enhancements

Backlog for the identity teaching library. Each new mechanism follows the same
convention: a self-contained directory (Flask + SQLite), verified end-to-end,
with a `client_example.py` and a README documenting the threat model.

## Planned new mechanisms

- [ ] **19 — OAuth2 Device Authorization Grant (RFC 8628)** — login for
  input-constrained devices (CLIs, TVs, IoT): the device shows a `user_code` +
  verification URL, polls `/token` while the user approves on a phone. Builds on
  the OAuth2 work (09/10).
- [ ] **20 — Magic link / email OTP (passwordless)** — sign in via a one-time,
  single-use, short-TTL link or code sent by email; covers token hashing,
  expiry, single-use, and rate-limiting. (Email delivery stubbed to console.)

## Other candidate mechanisms

- [ ] **XSS attack vs. defense (`22-xss`)** — a `vuln`-vs-`safe` demo in the
  style of `20-sql-injection`: an endpoint that reflects/stores user input with
  escaping **off** and **on**, plus a payload that steals a session cookie.
  Cover the three XSS types (reflected, stored, DOM-based) and the layered
  defenses: **contextual output encoding** (the primary fix — Jinja
  autoescaping, and why `| safe` / `Markup` reintroduce risk), a **Content-
  Security-Policy** (already set in 04's `set_security_headers` — show it
  blocking inline script), and **`HttpOnly` cookies** (03+, so an XSS can't read
  the session cookie). Tie it to the repo: mechanism 04 already ships CSP +
  `HttpOnly`; this makes the threat they defend against concrete. Ship with a
  `test.py` (payload rendered inert on `/safe`, executable on `/vuln`; CSP
  header present).
- [x] **CSRF attack vs. defense (`21-csrf`)** — done: attacker page auto-submits
  a cross-site form; account takeover on `/vuln`, 403 on `/safe`; synchronizer
  token + `SameSite` + OAuth `state` covered; `test.py` passes.
- [ ] **CORS + browser SPA client (`cors-spa`)** — split the client and API
  onto **different origins** so CORS actually applies: a browser SPA (origin A)
  calling a bearer-token API (origin B). Show correct **preflight (`OPTIONS`)**
  handling, an explicit **origin allow-list** (not `*`), `Access-Control-Allow-
  Credentials` done right, and the common **misconfigurations** (reflecting any
  `Origin` with credentials). Teachable point: **CORS relaxes the same-origin
  policy — it is not a defense** (contrast with the CSRF protection in 04/09/10).
  Pairs naturally with the token APIs (06–08, 13). Alternatively, retrofit an
  origin-allow-listed CORS layer onto the resource server in `19-sso-mailbox`.
- [ ] **OAuth2 Token Exchange (RFC 8693)** — delegation / impersonation between
  services (act-as / on-behalf-of).
- [ ] **`private_key_jwt` client authentication (RFC 7523)** — asymmetric client
  auth at the token endpoint (vs. a client secret).
- [ ] **Account recovery** — password reset + TOTP/passkey recovery (backup
  codes), the flow attackers target most.
- [ ] **Signup + email verification** — self-service registration with a
  verified-email gate.
- [ ] **Risk-based / step-up auth** — require a stronger factor for sensitive
  actions (re-auth, WebAuthn UV).

## Enhancements to existing mechanisms

- [ ] **16-totp** — one-time **backup/recovery codes**; reject reuse of a code
  within its 30s step; account lockout + alerting.
- [ ] **17-webauthn** — **discoverable credentials** for usernameless login;
  require user verification (UV) for high-value actions; verify attestation.
- [ ] **14-saml** — Single Logout (SLO); encrypted assertions
  (`EncryptedAssertion`); sign the AuthnRequest; CSRF token on the IdP login.
- [ ] **15-spiffe** — trust-bundle **federation** across domains; SPIRE-style
  workload **attestation**; automatic short-TTL SVID rotation.
- [ ] **12-cert-bound / 13-dpop** — carry the binding across **refresh tokens**
  (08); RS256/JWKS signing (10).
- [ ] **10-oidc / 07-jwt** — JWKS key **rotation** (multiple `kid`s); `at_hash`
  binding of the id_token to the access token.
- [ ] **18-scim** — richer filters (`and`/`co`/`sw`), `sortBy`, Bulk operations,
  `ETag`/`If-Match` concurrency, soft-delete policy.
