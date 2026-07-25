"""
mailer.py — a stubbed email delivery channel.

A real deployment hands the message to an SMTP server or an email API
(SES/SendGrid/…). For a self-contained demo we "deliver" by:

  * printing the message to the server log, and
  * appending it to outbox.log next to the app,

so you (and test.py) can read the verification link without a mail server. The
link is what a user would receive and click.

Security note: the verification link is a *bearer* secret — anyone with the
link can verify the account. That's why it's single-use and short-lived
(see verify.py), and why in production it must only ever be sent over the
verified transport (email) and logged with care. We deliberately keep it out
of anything an attacker can read remotely.
"""

import os

OUTBOX = os.path.join(os.path.dirname(__file__), "outbox.log")


def send_verification_email(to_email: str, verify_url: str) -> None:
    body = (
        f"To: {to_email}\n"
        f"Subject: Confirm your email address\n\n"
        f"Welcome! Please confirm this address by opening:\n"
        f"  {verify_url}\n"
        f"This link is single-use and expires soon. If you didn't sign up, "
        f"you can ignore this email.\n"
        f"{'-' * 60}\n"
    )
    print("[mailer] verification email sent:\n" + body)
    with open(OUTBOX, "a") as f:
        f.write(body)


def send_already_registered_email(to_email: str) -> None:
    """Sent when someone tries to sign up with an address that already has an
    account. It goes to the real owner (not the requester), so the signup
    response can stay identical whether or not the email exists — closing the
    account-enumeration side channel — while still being helpful."""
    body = (
        f"To: {to_email}\n"
        f"Subject: You already have an account\n\n"
        f"Someone tried to sign up with this address, but it's already "
        f"registered. If that was you, just sign in. If not, no action is "
        f"needed — no account was created.\n"
        f"{'-' * 60}\n"
    )
    print("[mailer] already-registered notice sent:\n" + body)
    with open(OUTBOX, "a") as f:
        f.write(body)
