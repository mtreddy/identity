"""
client_example.py — a SOFTWARE AUTHENTICATOR that does what a phone/YubiKey does.

Real WebAuthn runs `navigator.credentials.*` in a browser talking to a hardware
authenticator. To exercise the server end-to-end (and to see exactly what the
device does), this file implements the authenticator in Python: it holds an EC
key, builds the attestation object / authenticatorData, and signs the challenge.

It runs the passkey registration + login, then shows the phishing/theft defenses:
wrong origin, a tampered signature, and a non-increasing counter (clone) are all
rejected.
"""

import hashlib
import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import webauthn as wa

BASE = os.environ.get("API_BASE", "http://localhost:5000").rstrip("/")
ORIGIN = os.environ.get("ORIGIN", BASE)
EMAIL = "user@example.com"


class SoftwareAuthenticator:
    def __init__(self):
        self.creds = {}   # credential_id -> [private_key, sign_count]

    def create(self, options, origin=ORIGIN):
        priv = ec.generate_private_key(ec.SECP256R1())
        cred_id = secrets.token_bytes(16)
        self.creds[cred_id] = [priv, 0]
        cose = wa.cose_from_ec_public(priv.public_key())
        auth_data = wa.build_authenticator_data(
            options["rp"]["id"], wa.FLAG_UP | wa.FLAG_UV | wa.FLAG_AT, 0,
            attested=(cred_id, cose))
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cdj = json.dumps({"type": "webauthn.create",
                          "challenge": options["challenge"], "origin": origin}).encode()
        return {"id": wa.b64url_encode(cred_id), "rawId": wa.b64url_encode(cred_id),
                "type": "public-key",
                "response": {"clientDataJSON": wa.b64url_encode(cdj),
                             "attestationObject": wa.b64url_encode(att_obj)}}

    def get(self, options, origin=ORIGIN, bump=True, tamper_sig=False):
        # An authenticator signs only with a credential it actually holds — pick
        # the first allowCredentials entry we have a key for.
        cred_id = next((wa.b64url_decode(c["id"]) for c in options["allowCredentials"]
                        if wa.b64url_decode(c["id"]) in self.creds), None)
        if cred_id is None:
            raise KeyError("no known credential in allowCredentials")
        priv, count = self.creds[cred_id]
        if bump:
            count += 1
            self.creds[cred_id][1] = count
        auth_data = wa.build_authenticator_data(
            options["rpId"], wa.FLAG_UP | wa.FLAG_UV, count)
        cdj = json.dumps({"type": "webauthn.get",
                          "challenge": options["challenge"], "origin": origin}).encode()
        sig = priv.sign(auth_data + hashlib.sha256(cdj).digest(),
                        ec.ECDSA(hashes.SHA256()))
        if tamper_sig:
            sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        return {"id": wa.b64url_encode(cred_id), "rawId": wa.b64url_encode(cred_id),
                "type": "public-key",
                "response": {"clientDataJSON": wa.b64url_encode(cdj),
                             "authenticatorData": wa.b64url_encode(auth_data),
                             "signature": wa.b64url_encode(sig)}}


_jar = http.cookiejar.CookieJar()
_op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_jar))


def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        r = _op.open(req)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def login(auth, **kw):
    _, options = post("/login/begin", {"email": EMAIL})
    return post("/login/finish", auth.get(options, **kw))


def main():
    auth = SoftwareAuthenticator()

    _, options = post("/register/begin", {"email": EMAIL})
    st, r = post("/register/finish", auth.create(options))
    print(f"1. register passkey            -> {st} {r.get('status', r)}")

    st, r = login(auth)
    print(f"2. login with passkey          -> {st} {r.get('email', r)}")

    st, r = login(auth, bump=False)
    print(f"3. login, counter not advanced -> {st} {r.get('detail', r)}  (clone detection)")

    st, r = login(auth, origin="http://evil.example")
    print(f"4. login from WRONG origin     -> {st} {r.get('detail', r)}  (phishing defense)")

    st, r = login(auth, tamper_sig=True)
    print(f"5. login with tampered sig     -> {st} {r.get('detail', r)}")


if __name__ == "__main__":
    if not BASE.startswith("http"):
        print("Set API_BASE."); sys.exit(2)
    main()
