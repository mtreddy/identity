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
- [x] Self-service **signup + email verification** — done as `25-signup-verification`:
  single-use, hashed, short-TTL token; verified-email login gate; no signup
  enumeration oracle; `test.py` passes (9 checks).
- [ ] **Admin / invite-based** user creation (create → invite → first-login
  password or passkey enrollment).
- [x] **SCIM 2.0** (`18-scim`) — IdP-driven create/update/deactivate/delete.
- [x] A short **reference** of which mechanisms need users and how each is seeded
  — done in `PROVISIONING.md` (Layer 1 table).

**Applications / clients** — relying parties, API clients, devices, workloads:
- [x] **OAuth2 Dynamic Client Registration (RFC 7591)** + management (RFC 7592)
  — done as `26-dynamic-client-registration`: initial-access-token gate,
  per-client registration access token (RFC 7592 read/update/delete),
  redirect-URI validation, scope clamping, confidential-client secret auth;
  `test.py` passes (15 checks).
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
- [x] **Session `SECRET_KEY`** and server-held signing secrets — a consistent
  `bootstrap` step across mechanisms, done as root `bootstrap.py` (provisions
  `SECRET_KEY`/`JWT_SECRET`/`REGISTRATION_TOKEN`/`API_TOKEN` into a gitignored
  `<dir>/.dev-secrets.env`, idempotent). DB **schema/migrations** remain per
  `seed.py` `init_schema()` for now.
- [x] A cross-cutting **`PROVISIONING.md`** documenting, per mechanism, exactly
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
- [x] **OAuth2 Token Exchange (RFC 8693)** — delegation / impersonation between
  services (act-as / on-behalf-of); demonstrated in `32-agent-obo` (agent acting
  on-behalf-of a user, `sub`/`act`, downscoping, `may_act`).
- [ ] **`private_key_jwt` client authentication (RFC 7523)** — asymmetric client
  auth at the token endpoint (vs. a client secret).
- [ ] **Account recovery** — password reset + TOTP/passkey recovery (backup
  codes), the flow attackers target most.
- [x] **Signup + email verification** — done as `25-signup-verification`
  (self-service registration with a verified-email gate).
- [ ] **Risk-based / step-up auth** — require a stronger factor for sensitive
  actions (re-auth, WebAuthn UV).

### Agent ↔ model authentication series

Design record: [AGENT_MODEL_AUTH.md](AGENT_MODEL_AUTH.md). An AI agent calling a
remote/local model, with mutual trust.

- [x] **Agent → model over OAuth** — done as `30-agent-model-oauth`: model
  gateway as an OAuth 2.1 Resource Server; agent auth via **`private_key_jwt`**
  (RFC 7523) + `client_secret`; **audience-bound** (RFC 8707/9728) + **scoped**
  tokens + per-client model allow-list; `jti` assertion replay protection;
  `/vuln` static-key foil. `test.py` passes (17 checks).
- [x] **Sender-constrained model token (DPoP)** — done as `31-agent-model-dpop`:
  the 30 token bound to the agent's DPoP key (`cnf.jkt`), fresh proof per call
  (htm/htu/jti/ath), stolen-token-inert on `/v1` vs replayable on the `/vuln`
  bearer foil; reuses `13`'s `dpop.py`. `test.py` passes (18 checks).
- [x] **`32-agent-obo`** — done: on-behalf-of delegation (RFC 8693 token
  exchange). Agent exchanges the user's subject token for a **downscoped** access
  token (`sub`=user, `act`=agent, authority = user ∩ agent); `may_act` pins the
  delegatee; `/v1` requires the OBO token, `/vuln` is the confused-deputy foil
  (agent's own token reaches a model the user may not use). `test.py` passes
  (18 checks). Also fills the **RFC 8693 token exchange** gap noted below.
- [ ] **`33-model-provenance`** — signed model manifest (id/version/digest) +
  optional TEE attestation the agent verifies; local-vs-remote parity.

### API-security series (REST → GraphQL → gRPC)

The authorization bugs that authentication doesn't fix, one directory per API
style (each `/vuln` vs `/safe`, OWASP API Security Top 10):

- [x] **REST API authorization** — done as `27-rest-api-authz`: BOLA/IDOR,
  BFLA, mass assignment, excessive data exposure (API1/3/5/6) with bearer-authed
  callers; object-, function-, and field-level checks + a response allow-list;
  `test.py` passes (14 checks).
- [ ] **GraphQL security (`28-graphql-security`)** — introspection left on vs
  disabled; query **depth/complexity/alias-batching** DoS vs cost limits;
  **field-level authorization** enforced in resolvers (the GraphQL form of
  BOLA), not just at the query root.
- [ ] **gRPC security (`29-grpc-security`)** — per-RPC authorization via
  **interceptors**, token-in-**metadata** propagation, **server reflection**
  exposure (the introspection analog), and message-size limits; builds channel
  auth on `11-mtls`. NOTE: departs from the Flask+SQLite convention
  (`grpcio`/`protobuf`, a `.proto`) — a deliberate, documented exception.

### Detection & audit pipeline

- [x] **SIEM audit webhook** — done as `34-siem-audit-webhook`: the
  *"ship logs to alerting"* step every mechanism ends on, done safely.
  Structured audit events **HMAC-signed** (`ts.nonce.body`) and POSTed to a
  receiver that verifies authenticity + freshness + nonce before storing;
  `/vuln/ingest` accepts a forged `role.granted admin` and a replay. `test.py`
  passes (9 checks). Further: shared nonce store, retries/DLQ, JWS for fan-out.

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
