# 19 — "Sign in with SSO, then read your mailbox"

A concrete **authenticate → authorize → access a resource** demo built on OpenID
Connect (mechanism 10). A third-party app, **MailViewer**, uses SSO to:

1. **authenticate** the user (OIDC `id_token` — *who* logged in), and
2. get the user's **consent** to the `mail:read` scope, then
3. **read the user's inbox** from the resource server with the access token.

The resource is a **mock mailbox** — fake email seeded in SQLite — so there's no
real mail server to run. MailViewer never sees the password; it only gets a
scoped token.

## The three roles (one app for a self-contained demo)

| Role | Endpoints |
|------|-----------|
| **Authorization server** | `/login`, `/authorize`, `/authorize/decision`, `/token`, `/.well-known/openid-configuration`, `/.well-known/jwks.json` |
| **Resource server (mailbox)** | `/userinfo`, **`/api/mailbox`** (scope `mail:read`) |
| **Client (MailViewer)** | `/`, `/client/start`, `/client/callback` |

## What's different from mechanism 10
This *is* the OIDC mechanism, reskinned so the protected resource is a mailbox:
the `resources` table became a **`messages`** table (from/subject/body/received/
unread), `/api/resources` became **`/api/mailbox`**, and the scope
`resources:read` became **`mail:read`**. Everything else — Authorization-Code +
PKCE, `state`/`nonce`, RS256-signed `id_token` verified via JWKS, one-time
codes, exact `redirect_uri` allow-list — is unchanged. See `10-openid-connect`
for the deep dive on those.

## Run it

```bash
cd 19-sso-mailbox
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export OIDC_ISSUER=http://127.0.0.1:5000        # must match where you serve
export PUBLIC_BASE_URL=http://127.0.0.1:5000
python seed.py           # user + MailViewer client + a seeded inbox
python app.py            # open http://127.0.0.1:5000
```

Click **Connect my mailbox**, log in as
`user@example.com` / `correct-horse-battery-staple`, approve the `mail:read`
consent — MailViewer then shows your inbox, having read it with the access token.

Headless (raw protocol + prints the inbox):

```bash
export OIDC_ISSUER=http://127.0.0.1:5000
python client_example.py
```

## The authorize-to-access story it makes tangible
- **Consent gates the mailbox.** The user explicitly approves *"Read the messages
  in your mailbox"* on the consent screen — that's what puts `mail:read` in the
  token.
- **The scope is enforced at the resource.** `/api/mailbox` requires `mail:read`;
  an access token that only has `openid` (identity) but not `mail:read` gets a
  **403 insufficient_scope**. Authentication ≠ authorization.
- **The app never holds your password** — only a short-lived, scoped access token
  (and it learns *who you are* from the separately-verified `id_token`).

## Swapping in a different resource
The mailbox is just a table + one scoped endpoint. To make this a "read your
files / calendar / transactions" demo instead, rename `messages`, seed different
rows, and adjust the scope name — the SSO machinery doesn't change. To use a real
provider's mail instead of the mock, you'd build a separate OAuth *client* that
talks to that provider (e.g. Google + Gmail API); that can't be verified headless
like this one, which is why the mock mailbox is the default.

## Threats addressed
Same as mechanism 10 (signed/nonce-bound `id_token`, PKCE, one-time codes,
exact redirect-URI allow-list, per-client scope allow-list + user consent), with
the added point that **least-privilege scope** (`mail:read`) is what actually
authorizes reading the mailbox — nothing broader is granted.
