# 01 — Login + Password

The first identity mechanism: authenticate a user with an **email + password**
and let them into a **protected web page** that shows resources only they own.

Everything is self-contained on your machine:

- **Web server:** Flask (Python)
- **Backend / DB:** SQLite — a single file, `identity.db`, no server to run
- **Secret handling:** passwords stored as **salted bcrypt hashes**, never plaintext

## Files

| File                     | Role                                                        |
|--------------------------|-------------------------------------------------------------|
| `db.py`                  | Data layer: schema, bcrypt hashing, user/resource queries   |
| `seed.py`                | Creates the DB with sample users + resources                |
| `app.py`                 | Flask web server: `/login`, `/dashboard`, `/logout`         |
| `templates/login.html`   | Login form                                                  |
| `templates/dashboard.html` | Protected page shown after login                          |

## Run it

```bash
cd 01-login-password

# 1. Isolated environment + dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Create the database with sample data
python seed.py

# 3. Start the server
python app.py
```

Open http://127.0.0.1:5000 and log in with:

- `alice@example.com` / `correct-horse-battery-staple`
- `bob@example.com` / `hunter2`

Log in as Alice and you'll see Alice's resources; Bob only sees Bob's.

## How the mechanism works

1. **Storage** — `seed.py` calls `db.create_user`, which bcrypt-hashes the
   password (`db.hash_password`) and stores only the hash in the `users` table.
2. **Login** — `POST /login` looks up the user by email and calls
   `db.verify_password`, which bcrypt-checks the attempt against the stored
   hash. Same generic error for "no such user" and "wrong password" so we
   don't leak which accounts exist.
3. **Session** — on success, the user id is placed in a Flask **signed session
   cookie**. The browser can't forge it because it's signed with `SECRET_KEY`.
4. **Protection** — `/dashboard` uses the `@login_required` decorator: no valid
   session → redirect to `/login`.

## Flow — how the communication starts and finishes

Communication **starts** with a plain-HTTP `GET /login` — there is no TLS, so
the password below travels in cleartext (⚠️). The **signed session cookie** is
the thread that carries identity across requests, but it's signed with a
hard-coded `SECRET_KEY` anyone reading the source can forge (⚠️). It **finishes**
when `session.clear()` empties that cookie at logout. The ⚠️ points are exactly
what `../02-secrets-transport` turns into 🔒 — `diff -ru 01-login-password
02-secrets-transport` and compare the two Flow sections.

```
  ┌──────────┐            ┌─────────────────────┐          ┌───────────┐
  │ Operator │            │  Flask app (app.py) │          │ identity  │
  │  / shell │            │   127.0.0.1:5000    │          │  .db      │
  └────┬─────┘            └──────────┬──────────┘          └─────┬─────┘
       │                             │                           │
  ═════╪═════ BOOT ══════════════════╪═══════════════════════════╪═══════
       │                             │                           │
       │ python seed.py ────────────────── create users ───────► │ bcrypt
       │                             │                           │ hashes
       │ python app.py ─────────────►│                           │
       │                             │ secret_key hard-coded  ⚠️ │
       │                             │ debug=True             ⚠️ │
       │        listening on HTTP    │ (plain HTTP, no TLS)   ⚠️ │

  ┌──────────┐                       │
  │ Browser  │                       │
  └────┬─────┘                       │
       │                             │
  ═════╪═════ START: LOGIN (cleartext) ══════════════════════════════════
       │                             │
       │  GET /login ───────────────►│   ← no TLS handshake; everything
       │◄──────── 200 login.html ────│     below is readable on the wire ⚠️
       │                             │
       │  POST /login                │
       │  email + password (cleartext)►│
       │                             │  get_user_by_email(email) ──► │
       │                             │◄───────────── user row ────────│
       │                             │  verify_password()
       │                             │  bcrypt.checkpw (constant-time)
       │                             │
       │                             │  ✔ match: session.clear();
       │                             │    session["user_id"]=…;
       │                             │    cookie signed w/ hard-coded key⚠️
       │  302 → /dashboard           │
       │◄─ Set-Cookie: session=…sig ─│
       │                             │  ✘ no match → "Invalid email or
       │                             │    password." (re-render form)

  ═════════ AUTHENTICATED REQUEST ══════════════════════════════════════
       │                             │
       │  GET /dashboard             │
       │  Cookie: session=…sig ─────►│
       │                             │  verify cookie signature
       │                             │  (key is guessable → forgeable) ⚠️
       │                             │  login_required → redirect if none
       │                             │  get_resources_for_user() ──► │
       │                             │◄──────────── resources ────────│
       │◄──────── 200 dashboard.html │

  ═════════ FINISH: LOGOUT ═════════════════════════════════════════════
       │                             │
       │  GET /logout ──────────────►│
       │                             │  session.clear()
       │◄─ 302 → /login; Set-Cookie: session= (empty)
       │                             │
       ▼                             ▼
   session over                 cookie invalidated
```

## What is intentionally NOT production-grade (yet)

These are the natural next steps in the series:

- `SECRET_KEY` is hard-coded — real apps load it from a secret/env var.
- No HTTPS — a real login must run over TLS so the password isn't sent in clear.
- No rate limiting / lockout on repeated failed logins.
- No self-service signup, email verification, or password reset.
- Session cookie flags (`Secure`, `HttpOnly`, `SameSite`) not yet hardened.

## Reset

Delete `identity.db` and re-run `python seed.py` for a clean slate.
