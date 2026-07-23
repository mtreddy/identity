"""
seed.py — create the demo user (resource owner) at the IdP.

Run once:  python seed.py
The IdP signing key + cert are generated separately on first server start.
"""

import db

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"


def main():
    db.init_schema()
    if db.get_user_by_email(USER_EMAIL):
        print(f"user already exists: {USER_EMAIL}")
    else:
        db.create_user(USER_EMAIL, USER_PASSWORD, name="Ada Lovelace")
        print(f"created user: {USER_EMAIL} / {USER_PASSWORD}  (name: Ada Lovelace)")
    print("\nStart the server:  python app.py")
    print("Open http://127.0.0.1:5000/ and click 'Sign in with SSO',")
    print("or drive the flow with:  python client_example.py")


if __name__ == "__main__":
    main()
