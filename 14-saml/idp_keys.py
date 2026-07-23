"""
idp_keys.py — the IdP's RSA signing key + self-signed certificate.

The Identity Provider signs every SAML assertion with this private key. Service
Providers verify assertions using the matching certificate, which the IdP
publishes in its metadata. (In mechanism 10 the same role was played by the
OIDC signing key + JWKS; SAML uses X.509 certs in metadata instead.)

Generated on first run and cached to disk (git-ignored).
"""

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KEY_PATH = Path(os.environ.get("IDP_KEY_FILE", Path(__file__).parent / "idp_key.pem"))
CERT_PATH = Path(os.environ.get("IDP_CERT_FILE", Path(__file__).parent / "idp_cert.pem"))


def _create():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "identity-14 IdP")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _load_or_create():
    if KEY_PATH.exists() and CERT_PATH.exists():
        key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
        return key, cert
    return _create()


PRIVATE_KEY, CERTIFICATE = _load_or_create()
PRIVATE_PEM = PRIVATE_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
CERT_PEM = CERTIFICATE.public_bytes(serialization.Encoding.PEM).decode()


def cert_b64_der() -> str:
    """The certificate as base64 DER, for the <ds:X509Certificate> in metadata."""
    import base64
    return base64.b64encode(
        CERTIFICATE.public_bytes(serialization.Encoding.DER)).decode()
