# Provisioning & bootstrap

Every mechanism in this repo authenticates *something* — a user, an app, a
workload. But authentication assumes the identity and its secrets already
**exist**. This document is the cross-cutting answer to "where did they come
from, and how would that work in production?" — the deliberate story behind the
ad-hoc `seed.py` init each directory does on first run.

Three layers get provisioned before first use:

1. **Users** — the humans (and their credentials) that log in.
2. **Applications / clients** — relying parties, API clients, devices, workloads.
3. **Server-side material** — the secrets, keys, and trust the server itself holds.

Two of these layers now have a dedicated, standardized mechanism in the library
(`25`, `26`); the rest are provisioned by each mechanism's `seed.py` (demo) and
mapped to their production source below.

---

## Layer 1 — Users

Who needs users, and how each gets them today:

| Mechanism | Needs users for | How seeded today | Production source |
|-----------|-----------------|------------------|-------------------|
| `01`–`05` | password login | `seed.py` hardcodes alice/bob | **`25-signup-verification`** (self-service) or admin/invite |
| `16-totp`, `17-webauthn` | 2FA / passkey enrollment on top of a user | `seed.py` user + enrollment | signup → enrollment ceremony |
| `09`,`10`,`19`,`24`,`26` | the resource owner who consents | `seed.py` `user@example.com` | your IdP's user directory |
| `14-saml` | the subject the IdP asserts | `seed.py` IdP user | enterprise IdP (AD/Okta/…) |
| `18-scim` | — (it *is* the provisioning API) | IdP drives CRUD | IdP → SCIM push |

**Standardized paths in the library:**

- **[`25-signup-verification`](25-signup-verification/)** — self-service signup
  gated by a single-use, short-TTL, hashed email-verification token. The primary
  self-provisioning path. Closes the account-enumeration side channel.
- **[`18-scim`](18-scim/)** — IdP-driven create/update/deactivate/delete (SCIM
  2.0). The enterprise counterpart: users are provisioned *into* the app by the
  IdP as people join and leave.

**Still on the backlog** (`TODO.md`): admin / invite-based creation
(create → invite → first-login password or passkey enrollment), and account
recovery / password reset (the same single-use-token machinery as `25`).

---

## Layer 2 — Applications / clients

The non-human relying parties. Each family has its own registration story:

| Mechanism | Client/identity | How issued today | Production source |
|-----------|-----------------|------------------|-------------------|
| `06`,`07`,`08`,`13` | **API key** | `seed.py` prints it once, stores the hash | key-issuance admin surface + rotation |
| `09`,`10`,`19`,`24` | **OAuth client** | `seed.py` writes an `oauth_clients` row | **`26-dynamic-client-registration`** (RFC 7591) |
| `11`,`12` | **workload cert (mTLS)** | `seed.py` CA signs client certs | CA / SPIRE enrollment (CSR → signed cert) |
| `15-spiffe` | **SVID** | `seed.py` mints X.509/JWT-SVIDs | SPIRE workload attestation + rotation |
| `14-saml` | **SP registration** | `seed.py` SP metadata + cert | SAML metadata exchange + cert rotation |
| `18-scim` | **provisioning token** | `seed.py` prints the bearer token | issued/rotated by the app to the IdP |
| `23-cors-spa` | **SPA API token** | env `API_TOKEN` | issued to the SPA's backend |

**Standardized path in the library:**

- **[`26-dynamic-client-registration`](26-dynamic-client-registration/)** —
  clients register themselves at `/register` (RFC 7591), gated by an initial
  access token, and manage themselves (RFC 7592) with a per-client registration
  access token. The redirect-URI allow-list is validated at registration and
  scopes are clamped to what the server supports. This replaces the hardcoded
  `oauth_clients` row for the OAuth family.

**Still on the backlog:** an API-key issuance/rotation surface (`06`–`08`/`13`),
CA/SPIRE workload enrollment (`11`/`12`/`15`), and SAML metadata exchange (`14`).

---

## Layer 3 — Server-side material

The secrets, keys, and trust the server holds. These split by *how they're
provisioned*:

| Material | Mechanisms | Demo source | Production source |
|----------|-----------|-------------|-------------------|
| Session `SECRET_KEY` | `02`–`05`,`09`,`10`,`14`,`16`,`17`,`19`,`21`,`22`,`24`,`25`,`26` | env / `bootstrap.py` | secret manager |
| HS256 `JWT_SECRET` | `07`,`08`,`09`,`12`,`13`,`19`,`24`,`26` | env / `bootstrap.py` | secret manager (KMS) |
| `REGISTRATION_TOKEN` | `26` | `bootstrap.py` | issued by the AS operator |
| `API_TOKEN` (SPA) | `23` | `bootstrap.py` (weak default otherwise) | issued to the SPA backend |
| RS256 keypair + **JWKS** | `10`,`19` | generated on first run (`oidc_private_key.pem`) | KMS/HSM, published at `/.well-known/jwks.json`, multi-`kid` rotation |
| **PKI**: CA + server/client certs | `11`,`12` | `seed.py` into `CERT_DIR` | internal CA / ACME + rotation |
| **SVID** trust bundle | `15` | `seed.py` into `SVID_DIR` | SPIRE server + trust-bundle federation |
| SAML IdP signing keypair | `14` | `seed.py` (`idp_key.pem`/`idp_cert.pem`) | IdP HSM + metadata cert rotation |
| DB schema | all | `seed.py` → `db.init_schema()` | migrations (Alembic/…) |

### `bootstrap.py` — the consistent step for server-held secrets

Instead of inventing `SECRET_KEY`/`JWT_SECRET`/… by hand for each mechanism,
`bootstrap.py` provisions strong values once into a gitignored
`<dir>/.dev-secrets.env` (mode `0600`), idempotently:

```bash
python bootstrap.py list          # what each mechanism needs
python bootstrap.py 26            # provision one (a prefix is enough)
python bootstrap.py --all         # every mechanism

cd 26-dynamic-client-registration
source .dev-secrets.env           # load the provisioned secrets
python seed.py && python app.py
```

It intentionally owns **only** the server-held env secrets. Everything else —
API keys, SCIM tokens, PKI certs, SVIDs, the SAML IdP keypair, the OIDC RSA key —
is *issued* material that stays with `seed.py` / first-run generation, because
issuance (and its hashing, printing-once, and rotation) is itself part of the
lesson in those mechanisms. In production every value in the "demo source"
column moves to a secret manager, KMS/HSM, or CA — never a file in the repo.

---

## The rule that ties it together

Two invariants hold across all three layers, and they're the reason provisioning
is a security topic and not just setup:

- **Secrets are shown once and stored hashed.** High-entropy secrets (API keys,
  registration tokens, verification tokens, client secrets, SVIDs) are printed
  or returned exactly once and persisted only as a SHA-256 hash — a fast hash is
  correct precisely because they're high-entropy (contrast bcrypt for
  low-entropy human passwords in `01`–`05`). A leak of the store can't be
  replayed into access.
- **Provisioning is an authorization boundary.** *Who* may create a user, register
  a client, enroll a workload, or issue a token is a privileged operation:
  `25` gates account activation on proving mailbox control, `26` gates
  registration on an initial access token and scopes management to a per-client
  token, `18` gates SCIM on a bearer token, and the PKI/SVID mechanisms gate
  issuance on the CA/attestation. Get provisioning wrong and every downstream
  authentication check is inheriting a compromised identity.
