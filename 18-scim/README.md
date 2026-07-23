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
