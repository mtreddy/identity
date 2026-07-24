"""seed.py — create the demo user, the device client, and some resources."""

import db

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"
CLIENT_ID = "smart-tv-app"


def main():
    db.init_schema()
    if db.get_user_by_email(USER_EMAIL):
        print(f"user already exists: {USER_EMAIL}")
        uid = db.get_user_by_email(USER_EMAIL)["id"]
    else:
        uid = db.create_user(USER_EMAIL, USER_PASSWORD, name="Ada Lovelace")
        db.add_resource(uid, "Playlist", "Focus — 42 tracks")
        db.add_resource(uid, "Continue watching", "Ep 3 · The Heist")
        print(f"created user: {USER_EMAIL} / {USER_PASSWORD}")

    db.create_client(CLIENT_ID, "Living-Room TV", ["profile", "resources:read"])
    print(f"registered device client: {CLIENT_ID} (scopes: profile resources:read)")
    print("\nStart the server:  python app.py")
    print("Run the device:    python client_example.py")


if __name__ == "__main__":
    main()
