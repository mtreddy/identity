"""
seed.py — create the demo user + resources, and DYNAMICALLY REGISTER the demo
client instead of hand-writing an oauth_clients row.

Contrast with 09, where the client was a literal db.create_oauth_client(...) call.
Here seed.py goes through the same registration path a real client would
(db.register_client on validated metadata) and records the resulting client_id
in demo_client.json so the browser demo can drive it.

It also reminds you of the *initial access token* the /register HTTP endpoint
requires (set REGISTRATION_TOKEN before starting the server, or OPEN_REGISTRATION=1
to allow anyone to register — see the README for why that's risky).

Run once:  python seed.py
"""

import json
import os
from pathlib import Path

import db
import registration

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
DEMO_CLIENT_FILE = Path(__file__).parent / "demo_client.json"

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"


def main():
    db.init_schema()

    if db.get_user_by_email(USER_EMAIL):
        print(f"user already exists: {USER_EMAIL}")
    else:
        uid = db.create_user(USER_EMAIL, USER_PASSWORD)
        db.add_resource(uid, "Trip itinerary", "Lisbon, Oct 3–10")
        db.add_resource(uid, "Bank note", "Move savings to the 4.2% account")
        print(f"created user: {USER_EMAIL} / {USER_PASSWORD}")

    # Register the demo (public) client through the real registration path.
    redirect_uri = PUBLIC_BASE_URL + "/client/callback"
    meta, err = registration.validate_metadata({
        "client_name": "Demo Web App (dynamically registered)",
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",     # public client -> PKCE, no secret
        "scope": "profile resources:read",
    })
    if err:
        raise SystemExit(f"demo client metadata invalid: {err}")
    created = db.register_client(meta)
    DEMO_CLIENT_FILE.write_text(json.dumps({
        "client_id": created["client_id"],
        "scope": meta["scope"],
    }))
    print(f"registered demo client: {created['client_id']}")
    print(f"  redirect_uri: {redirect_uri}")
    print("  (its registration_access_token was generated and discarded here —")
    print("   a real registrant would keep it to manage the client via RFC 7592)")

    if os.environ.get("REGISTRATION_TOKEN"):
        print("\n/register is gated by REGISTRATION_TOKEN (send it as a Bearer token).")
    else:
        print("\nSet REGISTRATION_TOKEN before starting the server so /register is")
        print("gated, e.g.:  export REGISTRATION_TOKEN=\"$(python -c 'import secrets;"
              " print(secrets.token_urlsafe(24))')\"")

    print(f"\nBrowse {PUBLIC_BASE_URL}/ and click through, or drive the raw")
    print("registration + flow with:  python client_example.py")


if __name__ == "__main__":
    main()
