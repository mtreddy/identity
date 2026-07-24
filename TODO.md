# TODO — future mechanisms & enhancements

Backlog for the identity teaching library. Each new mechanism follows the same
convention: a self-contained directory (Flask + SQLite), verified end-to-end,
with a `client_example.py` and a README documenting the threat model.

## Planned new mechanisms

- [x] **OAuth2 Device Authorization Grant (RFC 8628)** — done as `24-device-grant`:
  device_authorization + polling `/token` (authorization_pending / slow_down /
  access_denied / expired_token / one-time device_code) + browser approval;
  `test.py` passes (11 checks).
- [ ] **Magic link / email OTP (passwordless)** — sign in via a one-time,
  single-use, short-TTL link or code sent by email; covers token hashing,
  expiry, single-use, and rate-limiting. (Email delivery stubbed to console.)

## Provisioning & bootstrap (cross-cutting)

Today each mechanism's `seed.py` provisions its demo state ad-hoc — hardcoded
users, hardcoded clients, secrets from env vars, keys/certs generated on first
run. A real system needs a deliberate story for how the three layers get set up
before first use, and several of these are standardized mechanisms worth building.

**Users** — the identities that authenticate (needed by 01–05, 16, 17, and the
delegated flows 09/10/14/19/24):
- [ ] Self-service **signup + email verification** — the primary user-provisioning
  path (also listed under candidate mechanisms).
- [ ] **Admin / invite-based** user creation (create → invite → first-login
  password or passkey enrollment).
- [x] **SCIM 2.0** (`18-scim`) — IdP-driven create/update/deactivate/delete.
- [ ] A short **reference** of which mechanisms need users and how each is seeded.

**Applications / clients** — relying parties, API clients, devices, workloads:
- [ ] **OAuth2 Dynamic Client Registration (RFC 7591)** + management (RFC 7592)
  — replace the hardcoded `oauth_clients` rows in 09/10/19/24 with a real
  registration endpoint (client_id/secret issuance, redirect-uri allow-list mgmt).
- [ ] **API-key issuance / rotation** surface for 06/07/08/13 (today `seed.py`
  prints a key once) — an admin endpoint plus rotation/revocation UX.
- [ ] **Workload cert / SVID enrollment** for 11/12/15 — CA enrollment (CSR →
  signed cert) and SPIRE-style attestation instead of `seed.py` minting certs.
- [ ] **SAML metadata exchange** for 14 (SP/IdP metadata + cert rotation).
- [ ] **SCIM provisioning-token** issuance / rotation for 18.

**Server-side** — the secrets and trust the server itself holds:
- [ ] **Signing-key provisioning & rotation**: the HS256 `JWT_SECRET`
  (07/08/09/13/19/24) and the RS256 keypair + JWKS (10/19) — load from a secret
  manager (Vault/KMS/HSM), support multiple `kid`s for zero-downtime rotation.
- [ ] **PKI bootstrap**: CA + server cert + trust bundle (11/12/15) — an issuance
  pipeline, rotation, and (SPIFFE) trust-bundle federation.
- [ ] **Session `SECRET_KEY`** and DB **schema/migrations** — a consistent
  `bootstrap` step across mechanisms (vs. per-`seed.py` init on first run).
- [ ] A cross-cutting **`PROVISIONING.md`** documenting, per mechanism, exactly
  what must exist before first run (users, clients, secrets, keys, certs) and
  where each comes from in production.

## Other candidate mechanisms

- [x] **XSS attack vs. defense (`22-xss`)** — done: reflected + stored + DOM
  demos; raw `<script>` executes on `/vuln`, encoded to inert text on `/safe`;
  output encoding + CSP + HttpOnly covered; `test.py` passes.
- [x] **CSRF attack vs. defense (`21-csrf`)** — done: attacker page auto-submits
  a cross-site form; account takeover on `/vuln`, 403 on `/safe`; synchronizer
  token + `SameSite` + OAuth `state` covered; `test.py` passes.
- [x] **CORS + browser SPA client (`23-cors-spa`)** — done: two-origin setup
  (SPA + API on different ports); preflight, origin allow-list, credentials, and
  the reflect-any-origin misconfiguration; `test.py` passes (12 checks).
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
