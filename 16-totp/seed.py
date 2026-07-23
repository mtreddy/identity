"""
seed.py — create the demo user with TOTP already enabled.

Run once:  python seed.py

It prints the TOTP secret (normally private to the user's authenticator app) so
you can compute codes for testing — add it to an authenticator, or let
client_example.py derive codes from it.
"""

import db
import totp

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"


def main():
    db.init_schema()
    user = db.get_user_by_email(USER_EMAIL)
    if user:
        print(f"user already exists: {USER_EMAIL}")
        secret = user["totp_secret"]
    else:
        uid = db.create_user(USER_EMAIL, USER_PASSWORD, name="Ada Lovelace")
        secret = totp.generate_secret()
        db.set_totp(uid, secret, enabled=True)
        print(f"created user: {USER_EMAIL} / {USER_PASSWORD}")

    print(f"\nTOTP secret (Base32): {secret}")
    print(f"otpauth URI: {totp.provisioning_uri(secret, USER_EMAIL, 'identity-16')}")
    print(f"current code right now: {totp.now_code(secret)}")
    print("\nStart the server:  python app.py")
    print(f"Headless demo:  TOTP_SECRET={secret} python client_example.py")


if __name__ == "__main__":
    main()
