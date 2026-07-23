"""
seed.py — create the user (mailbox owner), register the MailViewer client, and
fill the user's mailbox with fake messages.

Run once:  python seed.py

The client's redirect URI must exactly match where you run the app. It is built
from PUBLIC_BASE_URL (default http://127.0.0.1:5000). If you serve on another
port, set PUBLIC_BASE_URL to match, e.g.:

    PUBLIC_BASE_URL=http://127.0.0.1:5019 python seed.py
"""

import os

import db

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:5000")

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"

CLIENT_ID = "mailviewer-app"

# from_addr, subject, body, received_at, unread — the mock inbox.
FAKE_MAILBOX = [
    ("payroll@acme.example", "Your October payslip is available",
     "Hi Ada, your payslip for October is ready to view in the portal.",
     "2026-10-31T09:12:00Z", 1),
    ("no-reply@bank.example", "Statement ready",
     "Your monthly statement for account ****4210 is now available.",
     "2026-10-28T18:03:00Z", 1),
    ("team@project.example", "Re: launch checklist",
     "Thanks — I've signed off on items 1–4. Can you take the deploy step?",
     "2026-10-27T14:40:00Z", 0),
    ("newsletter@devweekly.example", "This week in security",
     "Top read: sender-constrained tokens (DPoP) explained.",
     "2026-10-26T07:00:00Z", 0),
]


def main():
    db.init_schema()

    if db.get_user_by_email(USER_EMAIL):
        print(f"user already exists: {USER_EMAIL}")
        user_id = db.get_user_by_email(USER_EMAIL)["id"]
    else:
        user_id = db.create_user(USER_EMAIL, USER_PASSWORD, name="Ada Lovelace")
        for m in FAKE_MAILBOX:
            db.add_message(user_id, *m)
        print(f"created user: {USER_EMAIL} / {USER_PASSWORD}")
        print(f"  seeded {len(FAKE_MAILBOX)} messages into the mailbox")

    redirect_uri = PUBLIC_BASE_URL.rstrip("/") + "/client/callback"
    db.create_oauth_client(
        client_id=CLIENT_ID,
        name="MailViewer",
        redirect_uris=[redirect_uri],
        allowed_scopes=["openid", "profile", "email", "mail:read"],
        is_public=1,
    )
    print(f"registered OAuth client: {CLIENT_ID} (MailViewer)")
    print(f"  redirect_uri: {redirect_uri}")
    print(f"  allowed scopes: openid profile email mail:read")
    print(f"\nOpen {PUBLIC_BASE_URL}/ and click 'Connect my mailbox',")
    print("or drive the raw protocol with:  python client_example.py")


if __name__ == "__main__":
    main()
