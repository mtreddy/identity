# 09 — OAuth2 Authorization Code + PKCE (delegated access)

The first **human-delegated** mechanism. A user (the *resource owner*) lets a
separate app (the *client*) access their data **without giving it their
password** — the app receives a scoped, short-lived access token instead. This
is "Log in with …" / "Connect your account".

It ties the series together: the user still authenticates with a **bcrypt
password** (mechanism 01), and the client walks away with a **JWT access token**
(mechanism 07).

## The three parties (all in one app for a runnable demo)

| Role | Endpoints | Who it is |
|------|-----------|-----------|
| **Authorization server** | `/login`, `/authorize`, `/authorize/decision`, `/token` | authenticates the user, gets consent, issues codes/tokens |
| **Resource server** | `/api/userinfo`, `/api/resources` | serves the user's data for a valid token |
| **Client app** | `/`, `/client/start`, `/client/callback` | the app requesting delegated access |

In production these are separate services; `app.py` keeps them in clearly
labelled sections.

## The flow

The **front channel** goes through the user's browser (redirects); the **back
channel** is a direct server-to-server call the browser never sees. PKCE ties
them together: the `code_challenge` travels the front channel, the matching
`code_verifier` only the back channel.

```mermaid
sequenceDiagram
    actor U as User + browser
    participant C as Client app (RP)
    participant A as Authorization server
    participant R as Resource server

    U->>C: 1. GET /client/start
    Note over C: build PKCE verifier + state;<br/>code_challenge = S256(verifier)
    C-->>U: 2. 302 → /authorize (client_id, redirect_uri,<br/>scope, state, code_challenge, S256)
    U->>A: 3. GET /authorize  (front channel)
    U->>A: 4. log in + grant consent
    A-->>U: 5. 302 → redirect_uri?code=…&state=…
    U->>C: 6. GET /client/callback?code&state
    Note over C: check state matches
    C->>A: 7. POST /token  (code + code_verifier)  — back channel
    Note over A: verify PKCE:<br/>S256(verifier) == code_challenge
    A-->>C: 8. access_token
    C->>R: 9. GET /api/resources (Authorization: Bearer)
    R-->>C: 10. the user's resources
```

> GitHub renders the block above as a diagram; the numbered walkthrough below is
> the text version.

### Step by step
1. **`GET /client/start`** — the user starts the "Connect" flow at the client.
2. The client generates a PKCE **`code_verifier`** (secret) and its hash
   **`code_challenge = S256(verifier)`**, plus a random **`state`**, and redirects
   the browser to the auth server's `/authorize` with those.
3–4. The auth server **authenticates** the user (password login) and asks for
   **consent** to the requested scopes.
5. On approval it redirects the browser back to the client's registered
   **`redirect_uri`** with a one-time **`code`** and the **`state`**.
6. The browser delivers the code to **`/client/callback`**; the client checks the
   returned `state` matches the one it sent (CSRF defense on the redirect).
7. The client calls **`POST /token`** (back channel) with the `code` **and the
   `code_verifier`**.
8. The auth server verifies **`S256(code_verifier) == code_challenge`** (PKCE) and
   returns the **access token**.
9–10. The client calls the **resource server** with `Authorization: Bearer`.

## Run it

```bash
cd 09-oauth2-auth-code-pkce
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py            # registers the demo client for http://127.0.0.1:5000
python app.py            # open http://127.0.0.1:5000 in a browser
```

Click **Connect & authorize**, log in as
`user@example.com` / `correct-horse-battery-staple`, approve consent — the demo
app then shows the profile + resources it fetched with its token.

Prefer to watch the raw protocol messages instead of a browser?

```bash
# (serve + seed on a matching base URL)
export PUBLIC_BASE_URL=http://127.0.0.1:5000
python client_example.py
```

## Why PKCE, and the other guardrails

- **PKCE (RFC 7636):** the client sends only `code_challenge = SHA-256(verifier)`
  up front and reveals the `verifier` at `/token`. An attacker who intercepts the
  authorization **code** still can't redeem it — they don't have the verifier.
  This is what makes the flow safe for public clients (SPAs, mobile, CLIs) that
  can't hold a secret. We **require** `S256`.
- **`state`:** an opaque random value the client checks on the callback —
  defeats CSRF on the redirect. (Verified in `/client/callback` and the script.)
- **Exact `redirect_uri` allow-list:** `/authorize` refuses (without redirecting)
  any redirect_uri not registered for the client, and `/token` re-checks it — this
  stops codes from being sent to an attacker-controlled URL.
- **One-time, short-lived codes:** `consume_auth_code` marks a code used inside a
  single UPDATE, so a replayed/intercepted code fails (`invalid_grant`). Codes
  live ~60s and are stored hashed.
- **Consent + scope allow-list:** the user explicitly approves specific scopes,
  and a client can't request scopes beyond what it's registered for.
- **Password login:** bcrypt (mechanism 01); the client never sees it.
- **CSRF tokens** on the login and consent forms (`/token` is exempt — it's an
  OAuth endpoint authenticated by the code + PKCE, not a browser form).

## Threats addressed

| Threat | Defense |
|--------|---------|
| App learns the user's password | it never does — delegation via token |
| Authorization code interception | PKCE (verifier never left the client) |
| CSRF on the redirect / login-CSRF | `state` + form CSRF tokens |
| Code sent to attacker's URL | exact redirect_uri allow-list (no redirect on mismatch) |
| Code replay | one-time codes (atomic mark-used), short TTL, hashed |
| Over-broad access | per-client scope allow-list + user consent |
| Token forgery | signed JWT, algorithm pinned, `aud`/`iss`/`exp` checked |

## Limitations / further hardening
Confidential clients (with a secret) authenticated at `/token`; refresh tokens
(reuse mechanism 08); OpenID Connect `id_token` for authentication (not just
authorization); `PS256`/asymmetric signing + JWKS; exact-vs-registered
redirect_uri matching for wildcards; rate-limiting `/login` and `/token`.
