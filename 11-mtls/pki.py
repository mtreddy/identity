"""
pki.py — a tiny X.509 Certificate Authority for the mTLS demo.

In mTLS, identity is a CERTIFICATE, not a token. This module is the trust root:
it creates a self-signed CA and issues certificates signed by it —

  * one SERVER certificate (so the client can verify the server), and
  * one CLIENT certificate per machine/agent (so the server can verify each
    client). The client's identity is its Subject Common Name (CN).

A certificate is just a public key + a subject name, signed by the CA's private
key. Because both sides trust the CA, each can verify the other's certificate
without any shared secret or prior direct exchange — that's the whole point.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_ca(common_name="identity-11 demo Root CA"):
    """Create a self-signed CA (its own issuer). This key SIGNS every other
    cert, so protecting it is the whole ballgame in a real PKI."""
    key = _new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        # BasicConstraints CA=True is what makes this cert allowed to sign others.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True, crl_sign=True, digital_signature=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue_cert(ca_cert, ca_key, common_name, *, server=False, ip=None, dns=None):
    """Issue a leaf cert signed by the CA. `server=True` marks it for TLS
    server auth (with SANs the client checks); otherwise it's a CLIENT cert
    marked for client auth, whose CN is the machine identity."""
    key = _new_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    )
    sans = []
    if dns:
        sans.append(x509.DNSName(dns))
    if ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def fingerprint(cert) -> str:
    """SHA-256 of the certificate's DER encoding — a stable id for one exact
    cert (used for our allow-list / revocation)."""
    return cert.fingerprint(hashes.SHA256()).hex()


# --- PEM file I/O -----------------------------------------------------------

def save_cert(path: Path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def save_key(path: Path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def load_cert(path: Path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)
