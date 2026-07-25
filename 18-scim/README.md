# 18 — SCIM 2.0 (provisioning & lifecycle)

The **lifecycle** layer that complements SSO (SAML 14 / OIDC 10). SSO logs a
user *in*; **SCIM** keeps the app's directory in sync with the Identity Provider
as people **join, change, and leave** — so accounts are created on hire and,
crucially, **deprovisioned on departure** automatically.

SCIM (RFC 7643 schema, RFC 7644 protocol) is a standard REST+JSON API the IdP
(Okta, Entra ID, …) calls to manage **Users** and **Groups**. This is a SCIM
**Service Provider** — the endpoint an IdP pushes changes to.

## Files

| File | Role |
|------|------|
| `scim.py` | SCIM schema mapping (row ↔ JSON), PATCH application, filter parsing, error/list shapes |
| `db.py` | `scim_users`, `scim_groups`, memberships, hashed provisioning tokens |
| `app.py` | the REST endpoints under `/scim/v2` (bearer-authed, `application/scim+json`) |
| `seed.py` | mints the provisioning bearer token (the IdP's credential) |
| `client_example.py` | simulates an IdP running the full user lifecycle |

## Endpoints (`/scim/v2`)

| Resource | Operations |
|----------|-----------|
| **Users** | `POST /Users`, `GET /Users/{id}`, `GET /Users?filter=&startIndex=&count=`, `PUT /Users/{id}`, `PATCH /Users/{id}`, `DELETE /Users/{id}` |
| **Groups** | `POST /Groups`, `GET /Groups/{id}`, `PATCH /Groups/{id}` (member add/remove/replace), `DELETE /Groups/{id}` |
| **Discovery** | `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` |

## Run it

```bash
cd 18-scim
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py           # prints the provisioning bearer token
python app.py            # http://127.0.0.1:5000

# in another shell — run the full lifecycle:
SCIM_TOKEN=<token> python client_example.py
```

By hand:

```bash
T=<token>
curl -H "Authorization: Bearer $T" -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a@b.com"}' \
  http://127.0.0.1:5000/scim/v2/Users
curl -H "Authorization: Bearer $T" \
  'http://127.0.0.1:5000/scim/v2/Users?filter=userName%20eq%20"a@b.com"'
```

## The lifecycle the client demonstrates
1. **Create** a user (POST) — provisioning on hire.
2. **Read** it (GET by id).
3. **Find** by `userName eq` filter — the IdP's dedup/reconcile lookup.
4. **Deactivate** (`PATCH` `active=false`) — the *most important* SCIM operation:
   disable access the moment someone leaves.
5. **Attribute change** (`PUT` full replace) — e.g. a name change.
6. **Uniqueness**: a duplicate `userName` → `409` with `scimType: uniqueness`.
7. **Group membership** — add and remove members via `PATCH`.
8. **Delete** (deprovision) → `204`; subsequent GET → `404`.

## SCIM specifics shown
- `application/scim+json` content type; **ListResponse** and **Error** message
  schemas; `meta` with `resourceType`, `created`/`lastModified`, `location`, and
  a `version` ETag.
- **PATCH** (`PatchOp`) with `add`/`replace`/`remove` — both path-based
  (`active`, `name.familyName`) and Entra-style value-object replace.
- **Filtering** (`attr eq "value"`) and **pagination** (`startIndex`/`count`).

## Threats / operational notes
- **Deprovisioning is the security point**: SCIM exists so that "removed in the
  IdP" reliably becomes "no access in the app" — orphaned accounts are a common
  breach vector.
- The provisioning token is high-value (it can create/delete any account): store
  it hashed (done here), scope it, rotate it, and rate-limit the endpoint.
- Further: `sortBy`, richer filters (`and`/`co`/`sw`), Bulk operations,
  `ETag`/`If-Match` concurrency, soft-delete policies, and per-attribute
  authorization.

  **SCIM 2.0 (System for Cross-domain Identity Management)** is an open-standard REST and JSON-based protocol designed to automate user identity provisioning and deprovisioning across enterprise systems.

While Single Sign-On (SSO) protocols like SAML and OpenID Connect manage *authentication* when a user logs in, SCIM operates continuously in the background to keep user directories synchronized between an Identity Provider (IdP, like Okta or Microsoft Entra ID) and a Service Provider (SP, like a SaaS application).

Based on the [identity/18-scim/README.md](https://github.com/mtreddy/identity/tree/main/18-scim) file you are viewing, here is a detailed breakdown of how SCIM 2.0 works under the hood:

---

## 1. Core Architecture & Standards

SCIM 2.0 is defined by two main RFC specifications:

* **RFC 7643 (Schema):** Defines standard representations for identity objects, attributes, and relationships.
* **RFC 7644 (Protocol):** Defines the RESTful API endpoints, request/response formats, search filtering, and error handling.

### Roles

* **Identity Provider (IdP):** The source of truth (SCIM Client) that triggers API requests whenever an employee is hired, changes roles, or leaves.
* **Service Provider (SP):** The target application (SCIM Endpoint) that processes these API calls to create, update, or remove local accounts.

---

## 2. Standard Endpoints & Schema

All requests use the `application/scim+json` media type. The base path is typically `/scim/v2/`.

### Core Resources

* **`GET /Users` & `POST /Users`:** Retrieve or create user accounts.
* **`GET /Users/{id}` / `PUT /Users/{id}` / `PATCH /Users/{id}` / `DELETE /Users/{id}`:** Manage specific user lifecycles.
* **`POST /Groups` / `PATCH /Groups/{id}`:** Manage group resources and group memberships.

### Discovery Endpoints

SCIM endpoints expose metadata so IdPs can auto-discover supported features:

* **`GET /ServiceProviderConfig`:** Discovers supported capabilities (e.g., whether PATCH, filtering, or bulk operations are supported).
* **`GET /ResourceTypes`:** Lists available endpoint resources (e.g., Users, Groups).
* **`GET /Schemas`:** Details the specific attribute structures supported by the SP.

---

## 3. The Identity Lifecycle Operations

### Provisioning (On Hire)

When an employee joins, the IdP sends a `POST /Users` request with core profile fields:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "employee@example.com",
  "name": {
    "givenName": "Jane",
    "familyName": "Doe"
  },
  "emails": [{"value": "employee@example.com", "primary": true}],
  "active": true
}

```

### Reconciliation & Filtering

Before creating a user, IdPs run a search query to avoid creating duplicates:
`GET /Users?filter=userName eq "employee@example.com"`
If a duplicate username is created, the SP returns a `409 Conflict` error with `scimType: uniqueness`.

### Updates: `PUT` vs `PATCH`

* **`PUT` (Full Replacement):** Replaces the entire resource. Missing fields are typically cleared or reset.
* **`PATCH` (Partial Update):** Minimizes network traffic and race conditions by modifying specific attributes using operations (`add`, `replace`, `remove`).

### Deprovisioning (Offboarding — The Critical Security Control)

When an employee leaves, access must be revoked immediately:

1. **Deactivation (Primary):** The IdP sends a `PATCH` request setting `"active": false`. The app disables the account, killing active sessions without immediately purging data.
2. **Deletion (Optional):** The IdP sends `DELETE /Users/{id}`, returning a `204 No Content` status code.

---

## 4. Key Implementation Mechanisms

* **Filtering & Pagination:** Standardized filtering expressions like `filter=userName eq "jdoe"` allow IdPs to query subsets of data using pagination parameters (`startIndex` and `count`).
* **Group Management:** Group memberships are managed primarily via `PATCH /Groups/{id}` operations to add or remove user IDs from a group's `members` array.
* **Concurrency Control:** SCIM utilizes standard HTTP `ETag` headers alongside `If-Match` headers to prevent race conditions during concurrent updates.

---

## 5. Security & Threats

* **Orphaned Accounts:** The primary security objective of SCIM is eliminating "ghost accounts"—former employees who retain access because manual deprovisioning was missed.
* **Bearer Token Protection:** SCIM APIs are typically authenticated via long-lived Bearer Tokens. Because these tokens grant administrative control to create and delete any user account, they must be stored securely (hashed at rest), scoped appropriately, and regularly rotated.


When an Identity Provider (IdP) like Okta, Microsoft Entra ID, or Ping Identity is configured to automatically provision users to a downstream Service Provider (SP) or application, it acts as the SCIM client.

Based on the [18-scim repository](https://github.com/mtreddy/identity/tree/main/18-scim) you are viewing, here is the exact mechanical process an IdP uses to create a new user.

### 1. The Pre-Flight Check (Reconciliation)

Before blindly creating a user, a well-behaved IdP will first check if the user already exists in your application to avoid creating duplicates or to link an existing account.

It does this by sending a `GET` request with a filter, usually searching by the user's email or username:

```http
GET /scim/v2/Users?filter=userName eq "a@b.com"
Authorization: Bearer <provisioning_token>

```

* **If the SP returns a match:** The IdP links its internal record to the SP's returned `id` and might follow up with a `PUT` or `PATCH` to update any changed attributes.
* **If the SP returns 0 results:** The IdP proceeds to the creation step.

### 2. The Creation Request (POST)

To create the user (e.g., when an employee is hired or assigned to the app), the IdP sends a `POST` request to the `/Users` endpoint containing the user's identity data formatted according to the SCIM Core Schema (RFC 7643).

Here is the `curl` equivalent from the repository's examples:

```bash
curl -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/scim+json" \
     -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a@b.com"}' \
     http://127.0.0.1:5000/scim/v2/Users

```

A more complete payload from a production IdP usually includes names and emails:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "employee@example.com",
  "name": {
    "givenName": "Jane",
    "familyName": "Doe"
  },
  "emails": [
    {
      "value": "employee@example.com",
      "primary": true
    }
  ],
  "active": true
}

```

### 3. The Service Provider's Response

If the creation is successful, your application (the SP) must store the user in its database, generate a unique local ID, and respond with a `201 Created` HTTP status code.

The response body must echo back the created user object, injecting the new unique `id` and `meta` attributes (like the creation timestamp and location URI). The IdP saves this `id` so it knows exactly which record to `PATCH` or `DELETE` later when the user's role changes or they leave the company.

### Handling Conflicts

If the IdP attempts to create a user that already exists (for example, a duplicate `userName` that slipped past the pre-flight check), the SP should reject the request. As noted in the repository's lifecycle steps, the standard way to handle this is for the SP to return a `409 Conflict` status code with the specific error type:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "One or more of the attribute values are already in use or are reserved."
}

```


### Vulnerabilities and Security Risks in SCIM Implementations

While SCIM is explicitly designed to eliminate the massive security risk of orphaned accounts, poorly configured endpoints or logical flaws in how the data is processed can introduce severe vulnerabilities:

* **Overpowered Bearer Tokens:** SCIM APIs are traditionally secured by long-lived Bearer tokens. If a token is provisioned with default, tenant-wide scopes, it becomes a master key. If leaked, an attacker can create, modify, or delete any user or group across the entire system. To mitigate this, tokens must be strictly scoped, rotated frequently, and ideally bound to specific IPs or mutual TLS (mTLS) identities.
* **[Ghost Access](https://sec.co/blog/scim-provisioning-attacks-and-how-to-prevent-them) (Soft Delete Failures):** The most critical function of SCIM is deprovisioning. Typically, an Identity Provider (IdP) sends a `PATCH` request setting `"active": false` when an employee is terminated. However, many applications only disable UI logins but fail to kill active sessions, revoke API keys, or remove group permissions. This creates a lingering access window for offboarded users.
* **[Attribute Poisoning](https://sec.co/blog/scim-provisioning-attacks-and-how-to-prevent-them):** Service Providers often map incoming SCIM attributes (such as `department` or `costCenter`) directly to application roles and permissions. If the endpoint accepts custom or unvetted attributes without strict validation, an attacker who subtly manipulates their profile at the IdP level can trigger automated privilege escalation in downstream applications.
* **Frictionless Group Stuffing:** Because groups dictate access to sensitive data, automated group management is a high-value target. If an application's SCIM endpoint allows bulk additions without rate limits, approval gates, or anomaly detection, a single compromised IdP connector can silently stuff high-privilege groups with rogue accounts.
* **Replay Attacks & Sync Storms:** Provisioning systems are noisy and frequently retry failed requests. If the SCIM endpoint is not designed with idempotency keys and deduplication checks, an attacker can capture and replay network requests. This can result in duplicate accounts, unauthorized memberships, or the accidental restoration of previously removed permissions.
* **[Parallel Provisioning](https://www.authgear.com/post/what-is-scim-provisioning/) Conflicts:** Running SCIM alongside Just-In-Time (JIT) provisioning—such as auto-creating accounts during a SAML login—without strict, stable identifier matching can cause the system to create duplicate user records. This identity fragmentation leads to authorization conflicts and auditing blind spots.

---

Are you currently implementing your own SCIM endpoint, and if so, how are you handling the scoping and lifecycle of the provisioning tokens?
