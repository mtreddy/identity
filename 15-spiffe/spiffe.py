"""
spiffe.py — SPIFFE primitives (stateless helpers).

SPIFFE gives every workload a URI identity:

    spiffe://<trust-domain>/<path>      e.g. spiffe://example.org/workload/billing

That identity is delivered as an **SVID** (SPIFFE Verifiable Identity Document)
in one of two forms:

  * X.509-SVID — an X.509 certificate with the SPIFFE ID in its **URI SAN**
    (NOT the Subject CN). Workloads present it in mTLS; the peer is identified by
    the SPIFFE ID, verified against the trust bundle (the trust domain's CA).
  * JWT-SVID — a JWT with `sub` = SPIFFE ID and `aud` = the intended recipient,
    signed by the trust domain and verified against its public keys (a JWKS-like
    bundle). For calls where mTLS isn't available end to end.

This module builds and reads both; `trust.py` holds the issuing keys/bundle.
"""

import datetime
from urllib.parse import urlparse

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

JWT_ALG = "RS256"


# --- SPIFFE IDs -------------------------------------------------------------

def is_spiffe_id(s: str) -> bool:
    p = urlparse(s or "")
    return p.scheme == "spiffe" and bool(p.netloc) and "@" not in p.netloc


def trust_domain(spiffe_id: str) -> str:
    return urlparse(spiffe_id).netloc


# --- X.509-SVID -------------------------------------------------------------

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def create_ca(trust_domain_name: str):
    """The trust bundle's root CA for a trust domain."""
    key = new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{trust_domain_name} CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue_x509_svid(ca_cert, ca_key, spiffe_id: str, ttl_hours: int = 24):
    """Issue an X.509-SVID: a leaf cert whose **URI SAN** is the SPIFFE ID.
    SPIFFE leaf certs deliberately leave the Subject empty and put identity in
    the SAN."""
    if not is_spiffe_id(spiffe_id):
        raise ValueError(f"not a SPIFFE ID: {spiffe_id}")
    key = new_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))               # identity lives in the SAN
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(hours=ttl_hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                   ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def spiffe_id_from_cert(cert) -> str | None:
    """Extract the SPIFFE ID from a cert's URI SAN (the SPIFFE way to identify a
    peer — never the CN)."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    for u in uris:
        if is_spiffe_id(u):
            return u
    return None


# --- JWT-SVID ---------------------------------------------------------------

def issue_jwt_svid(private_key, kid: str, spiffe_id: str, audience: str,
                   ttl_seconds: int = 300) -> str:
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {"sub": spiffe_id, "aud": audience, "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, private_key, algorithm=JWT_ALG, headers={"kid": kid})


def verify_jwt_svid(token: str, public_key, audience: str) -> str:
    """Verify a JWT-SVID against a trust-bundle key and required audience.
    Returns the SPIFFE ID (sub)."""
    claims = jwt.decode(token, public_key, algorithms=[JWT_ALG], audience=audience)
    sub = claims.get("sub")
    if not is_spiffe_id(sub):
        raise jwt.InvalidTokenError("sub is not a SPIFFE ID")
    return sub


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
