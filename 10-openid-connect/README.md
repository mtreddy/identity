# 10 — OpenID Connect (authentication on top of OAuth2)

Builds on [`../09-oauth2-auth-code-pkce`](../09-oauth2-auth-code-pkce/). OAuth2
answers *"can this app access the API?"* (**authorization**). OpenID Connect
adds *"who is the user, and can I prove it?"* (**authentication**) as a thin
layer on the same Authorization-Code + PKCE flow.

```bash
diff -ru ../09-oauth2-auth-code-pkce ./ | less
```

## What OIDC adds over 09

| Addition | What it is |
|----------|-----------|
| **`openid` scope** | Opts the request into OIDC; makes `/token` also return an id_token |
| **`id_token`** | A **signed JWT about the user** (`sub`, `email`, `name`, …) meant for the *client*, with `aud` = the client_id |
| **`nonce`** | Client-generated random value echoed inside the id_token, so the client detects a replayed/injected token |
| **RS256 + JWKS** | Tokens are now **asymmetrically** signed; clients verify with the public key from `/.well-known/jwks.json` (no shared secret) |
| **Discovery** | `/.well-known/openid-configuration` advertises endpoints, keys, algorithms |
| **UserInfo** | `/userinfo` returns identity claims for an `openid` access token |

### From HS256 (07–09) to RS256 (here)
Earlier mechanisms signed with a shared secret — anyone who can *verify* a token
can also *mint* one. OIDC id_tokens are consumed by many independent clients, so
we switch to **asymmetric** signing (`crypto_keys.py`): the provider holds the
RSA **private** key and signs; clients verify with the **public** key published
at JWKS. Each key has a `kid` so tokens name which key signed them, enabling
rotation.

## The two tokens

| | Access token | ID token |
|--|--|--|
| Answers | *authorization* (call the API) | *authentication* (who logged in) |
| Audience (`aud`) | the API | the **client_id** |
| Consumed by | resource server | the **client** |
| Client treats it as | opaque | **verifies & reads** it |

The client **must not** use the access token to identify the user — that token
wasn't issued *to* it. Identity comes from the verified id_token.

## Run it

```bash
cd 10-openid-connect
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py            # generates the RSA key on first run, registers the client
python app.py            # open http://127.0.0.1:5000
```

> `JWT_SECRET` is no longer needed — signing is asymmetric. The private key is
> written to `oidc_private_key.pem` (git-ignored) on first run; delete it to
> rotate. The token issuer defaults to `http://127.0.0.1:5000`; set
> `OIDC_ISSUER` (and seed with a matching `PUBLIC_BASE_URL`) to run elsewhere.

Click **Connect & authorize**, log in as
`user@example.com` / `correct-horse-battery-staple`, consent — the demo app
verifies the id_token against the provider's JWKS and shows **who you are**.

Raw protocol (also validates the id_token via discovery + JWKS):

```bash
export OIDC_ISSUER=http://127.0.0.1:5000
python client_example.py
```

Peek at the provider metadata:

```bash
curl -s http://127.0.0.1:5000/.well-known/openid-configuration | python -m json.tool
curl -s http://127.0.0.1:5000/.well-known/jwks.json | python -m json.tool
```

## How the client validates the id_token (the crux of OIDC)

1. Read the token's `kid` header → fetch the matching key from **JWKS**.
2. Verify the **RS256 signature** with that public key (algorithm pinned).
3. Check **`iss`** = the provider, **`aud`** = our own client_id, **`exp`** not passed.
4. Check **`nonce`** equals the value we generated for this login.

Only then does the client trust the claims (`sub`, `email`, …) as the user's
identity. `client_example.py` and `/client/callback` both do exactly this.

## Flow — how the communication starts and finishes

The Authorization-Code + PKCE skeleton is identical to `../09-oauth2-auth-code-pkce`
(front channel through the browser, back channel server-to-server). OIDC adds a
**second token** and a way to trust it: the client requests the `openid` scope +
a `nonce`, and `/token` returns an **id_token** (RS256-signed JWT *about the
user*, `aud` = client) alongside the access token. The client verifies the
id_token against the provider's **JWKS** public key — no shared secret. Marked
**★** below is everything new versus 09.

```
 actor User+browser        Client (RP)         OIDC Provider          Resource
      │                        │                    │                    server
 ═════╪═ DISCOVERY (once) ═════╪════════════════════╪═════════════════════════
      │                        │ GET /.well-known/openid-configuration ★ │
      │                        │◄── endpoints, jwks_uri, algs (RS256) ★──│
      │                        │ GET /.well-known/jwks.json  → cache ★    │
      │                        │◄── public keys keyed by `kid` ★ ────────│

 ═════╪═ FRONT CHANNEL: authorize (browser redirects) ══════════════════════
      │ GET /client/start ────►│ build PKCE verifier + state + nonce ★    │
      │◄─ 302 /authorize (…, scope="openid profile…", code_challenge,     │
      │      nonce ★) ─────────┤                    │                    │
      │ GET /authorize ───────────────────────────►│ authenticate user  │
      │ log in (bcrypt) + consent ─────────────────►│ (password, from 01)│
      │◄─ 302 redirect_uri?code=…&state=… ──────────│ (code bound to     │
      │                        │                    │  user+scope+nonce★+pkce)
      │ GET /client/callback (code, state) ───────►│                     │
      │                        │ state matches? ✔   │                    │

 ═════╪═ BACK CHANNEL: token exchange ═══════════════════════════════════════
      │                        │ POST /token (code + code_verifier) ────►│
      │                        │           verify PKCE: S256(verifier)==  │
      │                        │           code_challenge                 │
      │                        │◄─ 200 { access_token,                    │
      │                        │         id_token: eyJ…(RS256) ★ } ───────│
      │                        │                    │                    │
      │                        │ VALIDATE id_token ★:                     │
      │                        │  kid → JWKS key; verify RS256 sig;       │
      │                        │  iss==provider; aud==our client_id;      │
      │                        │  exp ok; nonce == the one we sent ★      │
      │                        │  → NOW we know WHO the user is            │

 ═════╪═ USE: call the API with the access token ═══════════════════════════
      │                        │ GET /api/resources  Bearer access_token ───────►│
      │                        │◄──────────── the user's resources ──────────────│
      │                        │ GET /userinfo (openid scope) ★ ─────────►│
      │                        │◄── {sub,email,name} (must match id_token) ★
      ▼                        ▼                    ▼                    ▼
  identity established   client trusts id_token,  "finish": access token expires;
  WITHOUT a shared secret  not the access token   id_token was a one-shot login proof
```

The crux (and the difference from 09): the client **must not** read the access
token to learn who logged in — that token's `aud` is the API, not the client.
Identity comes only from the **verified id_token**, whose `aud` is the client and
whose `nonce` ties it to this exact login. RS256 + JWKS means a party that can
*verify* a token can no longer *mint* one (unlike HS256 in 07–09).

## Threats addressed (beyond 09)

| Threat | Defense |
|--------|---------|
| Token forgery by a verifier | asymmetric RS256 — verifiers hold no signing key |
| id_token replay / injection | `nonce` binds the token to the client's request |
| Using an access token as proof of identity | separate id_token with `aud` = client |
| Token substitution across clients | `aud` in the id_token must equal the client_id |
| `alg:none` / algorithm confusion | algorithm pinned to RS256 on verify |

## Limitations / further hardening
Key **rotation** (multiple keys in JWKS, `kid`-driven) and cache-control on the
JWKS; `at_hash`/`c_hash` binding of the id_token to the access token/code;
signed/encrypted request objects (JAR/JARM); id_token `max_age`/`auth_time`
enforcement; refresh tokens (reuse mechanism 08); pairwise `sub` for privacy.
