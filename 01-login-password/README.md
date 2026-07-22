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

## What is intentionally NOT production-grade (yet)

These are the natural next steps in the series:

- `SECRET_KEY` is hard-coded — real apps load it from a secret/env var.
- No HTTPS — a real login must run over TLS so the password isn't sent in clear.
- No rate limiting / lockout on repeated failed logins.
- No self-service signup, email verification, or password reset.
- Session cookie flags (`Secure`, `HttpOnly`, `SameSite`) not yet hardened.

## Reset

Delete `identity.db` and re-run `python seed.py` for a clean slate.
