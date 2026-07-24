# 24 — OAuth2 Device Authorization Grant (RFC 8628)

Login for **input-constrained devices** — smart TVs, CLIs, IoT — that can't run
a browser redirect flow or take a typed password comfortably. The device shows a
short code and a URL; the user approves on a second device (their phone) with a
real browser; the device polls until it's approved and gets a token.

This is the "enter this code at example.com/device" flow you've used on a TV.

## The flow

```
 device                         auth server                      user's phone
   │  POST /device_authorization ──▶│                                 │
   │◀ device_code, user_code, ──────┤                                 │
   │   verification_uri, interval   │                                 │
   │                                                                  │
   │  shows: "go to <uri>, enter <user_code>"  ─────────────────────▶ │
   │                                │◀ open /device, enter code, ─────┤
   │                                │   log in, approve scopes        │
   │  POST /token (device_code) ───▶│  (repeat every `interval`s)     │
   │◀ authorization_pending ────────┤                                 │
   │  POST /token (device_code) ───▶│                                 │
   │◀ access_token ─────────────────┤  (once approved)                │
   │  GET /api/resources (Bearer) ─▶│                                 │
```

## Endpoints

| Endpoint | Who | Purpose |
|----------|-----|---------|
| `POST /device_authorization` | device | get a `device_code` + `user_code` |
| `POST /token` (`grant_type=…:device_code`) | device | poll for the token |
| `GET/POST /device` | user's browser | enter the `user_code` |
| `/login`, `/device/consent`, `/device/decision` | user's browser | authenticate + approve/deny |
| `GET /api/resources` | device | use the access token |

## Run it

```bash
cd 24-device-grant
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py
python app.py            # http://127.0.0.1:5000

# the device (prints the user_code, then polls):
python client_example.py
```

To do the human half yourself, run the device, then open the printed
`verification_uri` in a browser, enter the code, log in as
`user@example.com` / `correct-horse-battery-staple`, and click **Allow** — the
device's next poll returns a token. (`client_example.py` also simulates that
approval so it completes on its own.)

## The polling state machine (RFC 8628 §3.5)
`POST /token` returns one of, as a `400` with an `error`, until it succeeds:

| Response | Meaning | Device should |
|----------|---------|---------------|
| `authorization_pending` | user hasn't approved yet | keep polling at `interval` |
| `slow_down` | you polled faster than `interval` | add 5s to the interval |
| `access_denied` | user denied | stop |
| `expired_token` | the `device_code` expired | start over |
| *200 + access_token* | approved | use the token |

The server here enforces `slow_down` (polls closer together than `interval`),
expires codes after `DEVICE_CODE_TTL`, and makes each `device_code` **one-time**
(a second successful redemption → `invalid_grant`).

## Security notes
- **Two codes, two audiences.** The `user_code` is short and human-typed, so it's
  low-entropy — that's fine because it's only usable during a short window while
  the user is present, and approval still requires the user to **authenticate**.
  The `device_code` is the high-entropy secret (stored hashed) that actually
  redeems the token.
- **User authentication + consent** happen on a capable device (the phone), so
  the TV never sees the password — same delegation benefit as mechanism 09.
- **Phishing caveat (real-world):** because the user types a code into a URL they
  navigated to themselves, attackers try to trick users into approving a
  *device the attacker controls*. Mitigations: short expiry, clear consent
  screens naming the client, binding, and rate-limiting `/device`.
- `user_code` uses a base-20, vowel-free, unambiguous charset (RFC 8628 §6.1).

## Limitations / further hardening
`verification_uri_complete` + a QR code for one-tap approval; per-client poll
rate-limits; `openid`/id_token support (mechanism 10); refresh tokens
(mechanism 08); and binding the device_code to the client that requested it.
