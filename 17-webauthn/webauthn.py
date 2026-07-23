"""
webauthn.py — WebAuthn / FIDO2 ceremonies (RFC-ish; W3C WebAuthn Level 2).

WebAuthn authenticates with PUBLIC-KEY CRYPTOGRAPHY instead of a shared secret.
The authenticator (a phone's Secure Enclave, a YubiKey, or — in our tests — a
software authenticator) holds a private key; the server stores only the public
key. Login is a challenge the authenticator SIGNS, so nothing phishable is ever
sent or stored.

Two ceremonies, both here:

  * REGISTRATION (attestation): the authenticator makes a NEW keypair for this
    site and returns the public key inside an `attestationObject`.
  * AUTHENTICATION (assertion): the authenticator SIGNS
    `authenticatorData || SHA-256(clientDataJSON)` with that private key.

The phishing resistance comes from what's signed/checked: the **origin** (in
clientDataJSON) and the **RP ID hash** (in authenticatorData) must match this
site — a look-alike domain can't get a usable signature.

We hand-roll the security checks on `cryptography`; `cbor2` only decodes the
CBOR/COSE binary structures. Shared helpers here are used by BOTH the server
(verify_*) and the software authenticator in client_example.py (build_*).
"""

import base64
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# authenticatorData flag bits
FLAG_UP = 0x01   # user present
FLAG_UV = 0x04   # user verified (PIN/biometric)
FLAG_AT = 0x40   # attested credential data included (registration)


class WebAuthnError(Exception):
    pass


# --- base64url --------------------------------------------------------------

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


# --- COSE <-> EC key --------------------------------------------------------

def cose_from_ec_public(public_key) -> bytes:
    """Encode an EC P-256 public key as a COSE_Key (ES256)."""
    nums = public_key.public_numbers()
    return cbor2.dumps({
        1: 2,     # kty: EC2
        3: -7,    # alg: ES256
        -1: 1,    # crv: P-256
        -2: nums.x.to_bytes(32, "big"),
        -3: nums.y.to_bytes(32, "big"),
    })


def cose_to_ec_public(cose_bytes: bytes):
    d = cbor2.loads(cose_bytes)
    if d.get(1) != 2 or d.get(3) != -7 or d.get(-1) != 1:
        raise WebAuthnError("unsupported COSE key (need EC2/ES256/P-256)")
    x = int.from_bytes(d[-2], "big")
    y = int.from_bytes(d[-3], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


# --- authenticatorData (shared: authenticator builds, server parses) --------

def build_authenticator_data(rp_id: str, flags: int, sign_count: int,
                             attested: tuple | None = None) -> bytes:
    """rpIdHash(32) || flags(1) || signCount(4) || [attestedCredentialData]."""
    data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) \
        + sign_count.to_bytes(4, "big")
    if attested is not None:
        cred_id, cose_key = attested
        data += b"\x00" * 16                       # AAGUID (zeros for soft auth)
        data += len(cred_id).to_bytes(2, "big") + cred_id + cose_key
    return data


def _parse_authenticator_data(data: bytes):
    rp_id_hash = data[:32]
    flags = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    rest = data[37:]
    return rp_id_hash, flags, sign_count, rest


# --- server: registration (attestation) -------------------------------------

def verify_registration(*, client_data_json: bytes, attestation_object: bytes,
                        expected_challenge: bytes, expected_origin: str,
                        expected_rp_id: str):
    """Verify a registration response. Returns (credential_id, cose_public_key,
    sign_count). We accept `fmt: "none"` attestation (typical for passkeys)."""
    cd = json.loads(client_data_json)
    if cd.get("type") != "webauthn.create":
        raise WebAuthnError("wrong clientData type")
    if b64url_decode(cd.get("challenge", "")) != expected_challenge:
        raise WebAuthnError("challenge mismatch")
    if cd.get("origin") != expected_origin:
        raise WebAuthnError("origin mismatch")

    att = cbor2.loads(attestation_object)
    auth_data = att["authData"]
    rp_id_hash, flags, sign_count, rest = _parse_authenticator_data(auth_data)
    if rp_id_hash != hashlib.sha256(expected_rp_id.encode()).digest():
        raise WebAuthnError("rpIdHash mismatch")
    if not flags & FLAG_UP:
        raise WebAuthnError("user not present")
    if not flags & FLAG_AT:
        raise WebAuthnError("no attested credential data")

    # attestedCredentialData = aaguid(16) || len(2) || credId || COSE key
    cid_len = int.from_bytes(rest[16:18], "big")
    cred_id = rest[18:18 + cid_len]
    cose_key = rest[18 + cid_len:]
    cose_to_ec_public(cose_key)                    # validate it parses
    return cred_id, cose_key, sign_count


# --- server: authentication (assertion) -------------------------------------

def verify_assertion(*, client_data_json: bytes, authenticator_data: bytes,
                     signature: bytes, cose_public_key: bytes,
                     expected_challenge: bytes, expected_origin: str,
                     expected_rp_id: str, stored_sign_count: int) -> int:
    """Verify a login assertion. Returns the new sign count. Raises on any
    failure (bad origin/challenge/RP, invalid signature, or a counter that
    didn't advance — a sign of a cloned credential)."""
    cd = json.loads(client_data_json)
    if cd.get("type") != "webauthn.get":
        raise WebAuthnError("wrong clientData type")
    if b64url_decode(cd.get("challenge", "")) != expected_challenge:
        raise WebAuthnError("challenge mismatch")
    if cd.get("origin") != expected_origin:
        raise WebAuthnError("origin mismatch")

    rp_id_hash, flags, sign_count, _ = _parse_authenticator_data(authenticator_data)
    if rp_id_hash != hashlib.sha256(expected_rp_id.encode()).digest():
        raise WebAuthnError("rpIdHash mismatch")
    if not flags & FLAG_UP:
        raise WebAuthnError("user not present")

    # The signature is over authenticatorData || SHA-256(clientDataJSON).
    message = authenticator_data + hashlib.sha256(client_data_json).digest()
    public_key = cose_to_ec_public(cose_public_key)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise WebAuthnError("invalid signature")

    # Clone detection: a real authenticator's counter strictly increases.
    if sign_count != 0 or stored_sign_count != 0:
        if sign_count <= stored_sign_count:
            raise WebAuthnError("sign count did not increase (possible clone)")
    return sign_count
