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

## Flow — how the communication starts and finishes

Unlike every other mechanism here, the "client" is **another system** — the IdP
(Okta/Entra) — not a browser or an agent acting for itself. It authenticates
with a high-value **provisioning bearer token** (stored hashed) and drives a
person's whole lifecycle over `/scim/v2` in `application/scim+json`. The story
**starts** when someone is hired (create) and **finishes**, security-critically,
when they leave (deactivate/delete).

```
 ┌──────────────┐              ┌──────────────────────┐          ┌────────┐
 │ IdP          │              │ SCIM SP (app.py)     │          │ app.db │
 │ (Okta/Entra) │              │  /scim/v2            │          │        │
 └──────┬───────┘              └──────────┬───────────┘          └───┬────┘
        │  Authorization: Bearer <provisioning token> (hashed at rest)
 ═══════╪═ JOIN: provision on hire ═══════════════════════════════════════════
        │ POST /Users {userName, name, active:true} ─────────────► │ insert
        │◄─ 201 {id, meta:{location, version(ETag)}} ──────────────│
        │ GET /Users/{id} ──────────────────────────────────────► │
        │◄─ 200 user resource ────────────────────────────────────│
        │ GET /Users?filter=userName eq "a@b.com" (reconcile) ──► │
        │◄─ 200 ListResponse (0/1 result) ────────────────────────│
        │ POST /Users (duplicate userName) ─────────────────────► │
        │◄─ 409 {scimType:"uniqueness"} ──────────────────────────│

 ═══════╪═ MOVE: attribute + group changes ══════════════════════════════════
        │ PUT /Users/{id}  (full replace: e.g. name change) ────► │ replace
        │◄─ 200 updated resource ─────────────────────────────────│
        │ PATCH /Groups/{id} {op:add/remove members} ───────────► │ membership
        │◄─ 200 group ────────────────────────────────────────────│

 ═══════╪═ LEAVE: deprovision (THE security point) ═══════════════════════════
        │ PATCH /Users/{id} {op:replace, active:false} ─────────► │ active=0
        │◄─ 200 (access must actually be cut — not just UI login) │
        │ DELETE /Users/{id} ───────────────────────────────────► │ delete
        │◄─ 204 No Content ───────────────────────────────────────│
        │ GET /Users/{id} ──────────────────────────────────────► │
        │◄─ 404 (gone) ───────────────────────────────────────────│
        ▼                              ▼                           ▼
  directory stays in sync     "finish" = deactivate/delete; SCIM exists so that
                              "removed in the IdP" ⇒ "no access in the app"
```

The whole point sits in the **LEAVE** phase: orphaned accounts (someone removed
in the IdP but still live in the app) are a classic breach vector, so
`active=false`/`DELETE` must *actually* cut access — kill live sessions, API
keys, and group grants, not just block the next UI login (see *Attack vectors*
below).

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

### Attack vectors on the SCIM endpoint
- **Incomplete deactivation** — `active=false` that only blocks new UI logins but
  leaves live sessions, API keys, or group grants intact leaves a lingering
  access window. Deactivation must actually cut access.
- **Attribute poisoning → privilege escalation** — if incoming attributes
  (`department`, `roles`, group names) map straight to app permissions, an IdP-side
  profile edit can silently escalate. Validate/allow-list what you honor.
- **Group stuffing** — bulk `PATCH /Groups` membership adds are a fast path into
  privileged groups; rate-limit and (for sensitive groups) gate them.
- **Replay / sync storms** — provisioning clients retry aggressively; without
  idempotent handling a replayed request can resurrect a removed account or
  membership.
- **JIT-vs-SCIM duplicate identities** — running SCIM alongside SAML/OIDC
  just-in-time provisioning without a stable match key (e.g. `externalId`) forks
  one person into two records with divergent access.
