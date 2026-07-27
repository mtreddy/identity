# 27 — REST API authorization (BOLA / BFLA / mass assignment / data exposure)

The bugs that **authentication doesn't fix**. Every request here carries a
valid bearer token — the caller is logged in — yet the API still leaks and
escalates, because it skips *authorization*. This directory puts a
**vulnerable** and a **safe** version of four endpoints side by side and fires
the same authenticated request at both, in the shape of the OWASP API Security
Top 10.

> The `/vuln/*` endpoints are intentionally broken. This is a **localhost
> sandbox for learning API authorization**, running against its own SQLite —
> not something to deploy.

Where the earlier API mechanisms establish *who you are* — API keys (`06`),
JWTs (`07`), OAuth scopes (`09`/`19`) — this one is about *what you may do with
a valid identity*: the four checks that live at the endpoint, not at the token.

## The four bugs

| # | OWASP API | Endpoint | The missing check | `/vuln` | `/safe` |
|---|-----------|----------|-------------------|---------|---------|
| 1 | **API1 — BOLA / IDOR** | `GET /notes/<id>` | object-level: do you *own* this object? | returns any note by id | owner check → `404` for others |
| 2 | **API3 — Excessive data exposure** | `GET /me` | response shaping: which fields go on the wire? | dumps the whole row (`password_hash`, `recovery_code`, `is_admin`) | public-field allow-list |
| 3 | **API5 — BFLA** | `GET /admin/users` | function-level: may you call this operation *at all*? | any authenticated user | `is_admin` required → `403` |
| 4 | **API6 — Mass assignment** | `PATCH /me` | field-level: which fields may you *write*? | binds the whole body → set `is_admin:true` | writable-field allow-list |

BOLA (#1) is consistently the **#1 API vulnerability**: object ids are guessable
and the ownership check is easy to forget. BFLA (#3) is its function-level twin
— an admin route that was never linked in the UI but is reachable by anyone who
guesses the path (obscurity is not authorization).

## Files

| File | Role |
|------|------|
| `authz.py` | the authorization core: bearer auth decorator, the public-field serializer, and the two allow-lists (`PUBLIC_USER_FIELDS`, `WRITABLE_PROFILE_FIELDS`) the safe handlers use |
| `app.py` | `/login` + the four `/vuln` vs `/safe` endpoint pairs; each vulnerable handler is marked `DANGER` with the check it skips |
| `db.py` | parameterized SQLite (users, notes, tokens); `update_user` takes column names only from a fixed allow-list, so mass assignment can't become SQL injection |
| `seed.py` | resets the demo DB (users `alice`/`bob`/`admin`, two notes) |
| `client_example.py` | logs in and fires all four attacks at both variants |
| `test.py` | happy path + the security negatives for every bug |

## Run it

```bash
cd 27-rest-api-authz
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python app.py            # seeds + serves http://127.0.0.1:5000

# in another shell:
python client_example.py
```

By hand — the classic BOLA. Alice logs in and reads **Bob's** note:

```bash
T=$(curl -sX POST http://127.0.0.1:5000/login -H 'Content-Type: application/json' \
     -d '{"username":"alice@example.com","password":"correct-horse-battery-staple"}' \
     | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -H "Authorization: Bearer $T" http://127.0.0.1:5000/vuln/notes/2   # leaks bob's note
curl -H "Authorization: Bearer $T" http://127.0.0.1:5000/safe/notes/2   # 404
```

Accounts (all seeded): `alice@example.com` / `correct-horse-battery-staple`,
`bob@example.com` / `hunter2`, `admin@example.com` / `admin-pw-do-not-ship`.

## Threats addressed
| Threat | Defense (the `/safe` handler) |
|--------|-------------------------------|
| **BOLA / IDOR** — read another user's object by id | check `object.owner_id == caller.id`; return `404` (not `403`) so ids aren't an existence oracle |
| **BFLA** — call an admin-only function as a normal user | gate the route on the caller's role (`is_admin`) |
| **Mass assignment** — set a privileged field via a profile update | bind only an explicit **writable-field allow-list**, never the raw body |
| **Excessive data exposure** — sensitive columns leak in the response | serialize through a **public-field allow-list**, never `dict(row)` |
| **Existence oracle** — `403` vs `404` reveals which ids exist | unauthorized object access returns the same `404` as a missing one |

## Notes / further hardening
- **Authorize on the server, per object, every time** — never rely on the
  client hiding a button or a field, or on an id being hard to guess.
- Prefer **unguessable ids** (UUID/ULID) as defense in depth, but they are *not*
  a substitute for the ownership check — ids leak through logs, referers, URLs.
- Centralize the decision (a policy layer / decorator) so "who may do what" is
  reviewable in one place rather than re-implemented at each handler — see
  mechanism `19` for scope-based access and a policy module.
- Enforce a **response schema** (serializer / DTO) at the edge so new columns
  aren't exposed by default; validate request bodies against a schema too.
- Add rate limiting and object-level audit logging — BOLA is usually found by
  *enumeration*, which is detectable.
- This uses opaque bearer tokens for brevity; in production carry identity in a
  scoped, short-lived token (`07`/`08`) and still do all four checks above.

## GraphQL & gRPC
The same four failures recur with different surface area: in **GraphQL** the
object/field checks must live in the *resolvers* (a single query walks many
objects), and introspection is the data-exposure analog; in **gRPC** they live
in *interceptors*, and server reflection is the introspection analog. Those are
the next two mechanisms (`28-graphql-security`, `29-grpc-security`).
