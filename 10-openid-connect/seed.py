"""
seed.py — create the demo resource owner (user), register the demo OAuth
client, and add some resources owned by the user.

Run once:  python seed.py

The client's redirect URI must exactly match where you run the app. It is built
from PUBLIC_BASE_URL (default http://127.0.0.1:5000). If you serve on another
port, set PUBLIC_BASE_URL to match, e.g.:

    PUBLIC_BASE_URL=http://127.0.0.1:5009 python seed.py
"""

import os

import db

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:5000")

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"

CLIENT_ID = "demo-web-app"


def main():
    db.init_schema()

    if db.get_user_by_email(USER_EMAIL):
        print(f"user already exists: {USER_EMAIL}")
        user_id = db.get_user_by_email(USER_EMAIL)["id"]
    else:
        user_id = db.create_user(USER_EMAIL, USER_PASSWORD, name="Ada Lovelace")
        db.add_resource(user_id, "Trip itinerary", "Lisbon, Oct 3–10")
        db.add_resource(user_id, "Bank note", "Move savings to the 4.2% account")
        print(f"created user: {USER_EMAIL} / {USER_PASSWORD}")

    redirect_uri = PUBLIC_BASE_URL.rstrip("/") + "/client/callback"
    db.create_oauth_client(
        client_id=CLIENT_ID,
        name="Demo Web App",
        redirect_uris=[redirect_uri],
        allowed_scopes=["openid", "profile", "email", "resources:read"],
        is_public=1,
    )
    print(f"registered OAuth client: {CLIENT_ID}")
    print(f"  redirect_uri: {redirect_uri}")
    print(f"  allowed scopes: openid profile email resources:read")
    print(f"\nOpen {PUBLIC_BASE_URL}/ in a browser and click 'Connect & authorize',")
    print("or drive the raw protocol with:  python client_example.py")


if __name__ == "__main__":
    main()
