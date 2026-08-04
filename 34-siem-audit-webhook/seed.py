"""
seed.py — provisioning for the SIEM webhook demo.

There is no user database here; the only secret is the HMAC key the *sender* and
*receiver* SHARE to sign and verify events. This prints a fresh 256-bit key
ONCE — set it in both processes' environment as SIEM_SECRET. Re-run to mint a
new one (it is never stored, only printed).
"""

import os
import secrets


def main():
    if os.environ.get("SIEM_SECRET"):
        print("SIEM_SECRET is already set in this environment; reusing it.")
        return
    key = secrets.token_urlsafe(32)     # 32 bytes -> 256-bit shared HMAC secret
    print("Shared webhook secret — set it in BOTH the receiver and the sender:\n")
    print(f'  export SIEM_SECRET="{key}"\n')
    print("Printed once and not stored. Re-run seed.py to rotate it.")


if __name__ == "__main__":
    main()
