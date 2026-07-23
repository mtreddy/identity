"""
saml.py — SAML 2.0 Web Browser SSO: build requests, sign assertions, validate.

SAML federates identity by passing a signed XML **assertion** about the user
from an Identity Provider (IdP) to a Service Provider (SP) through the browser.
The trust is an **XML Digital Signature** over the assertion, made with the
IdP's private key and verified with its certificate.

We deliberately delegate the signature/canonicalization to `signxml` (a vetted
XML-DSig library). Rolling your own XML canonicalization is how real-world SAML
signature-wrapping / XSW vulnerabilities happen — so the correct lesson is
"use a reviewed library, and always read identity from the element the library
tells you was signed."

Bindings used:
  * SP -> IdP  AuthnRequest via HTTP-Redirect (DEFLATE + base64 in the URL)
  * IdP -> SP  Response via HTTP-POST (base64 in an auto-submitted form)
"""

import base64
import datetime
import secrets
import zlib

from lxml import etree
from signxml import XMLSigner, XMLVerifier

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NSMAP = {"samlp": SAMLP, "saml": SAML}

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


class SamlError(Exception):
    """Any SAML request/response that fails a structural or security check."""


# --- small helpers ----------------------------------------------------------

def _id() -> str:
    return "_" + secrets.token_hex(16)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _t(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_t(s: str):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)


def deflate_b64(xml: str) -> str:
    """DEFLATE + base64 for the HTTP-Redirect binding (raw deflate, no header)."""
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(co.compress(xml.encode()) + co.flush()).decode()


def inflate_b64(s: str) -> str:
    do = zlib.decompressobj(-15)
    return (do.decompress(base64.b64decode(s)) + do.flush()).decode()


def b64(xml: str) -> str:
    return base64.b64encode(xml.encode()).decode()


def unb64(s: str) -> str:
    return base64.b64decode(s).decode()


def _q(el, ns, tag):
    return el.find(f"{{{ns}}}{tag}")


# --- SP: build an AuthnRequest ----------------------------------------------

def build_authn_request(sp_entity_id: str, acs_url: str, idp_sso_url: str):
    """Return (request_id, xml). The SP keeps request_id to match InResponseTo."""
    rid = _id()
    root = etree.Element(f"{{{SAMLP}}}AuthnRequest", nsmap=NSMAP)
    root.set("ID", rid)
    root.set("Version", "2.0")
    root.set("IssueInstant", _t(_now()))
    root.set("Destination", idp_sso_url)
    root.set("AssertionConsumerServiceURL", acs_url)
    root.set("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    issuer = etree.SubElement(root, f"{{{SAML}}}Issuer")
    issuer.text = sp_entity_id
    return rid, etree.tostring(root).decode()


def read_authn_request(xml: str) -> dict:
    root = etree.fromstring(xml.encode())
    return {
        "id": root.get("ID"),
        "issuer": _q(root, SAML, "Issuer").text,
        "acs_url": root.get("AssertionConsumerServiceURL"),
    }


# --- IdP: build a signed Response -------------------------------------------

def build_signed_response(*, idp_entity_id, sp_entity_id, acs_url, in_response_to,
                          user, key_pem, cert_pem, validity_seconds=300):
    """Build a SAML Response whose Assertion is signed with the IdP key."""
    now = _now()
    not_after = now + datetime.timedelta(seconds=validity_seconds)
    aid = _id()

    resp = etree.Element(f"{{{SAMLP}}}Response", nsmap=NSMAP)
    resp.set("ID", _id())
    resp.set("Version", "2.0")
    resp.set("IssueInstant", _t(now))
    resp.set("Destination", acs_url)
    resp.set("InResponseTo", in_response_to)
    etree.SubElement(resp, f"{{{SAML}}}Issuer").text = idp_entity_id
    status = etree.SubElement(resp, f"{{{SAMLP}}}Status")
    etree.SubElement(status, f"{{{SAMLP}}}StatusCode").set("Value", STATUS_SUCCESS)

    a = etree.SubElement(resp, f"{{{SAML}}}Assertion")
    a.set("ID", aid)
    a.set("Version", "2.0")
    a.set("IssueInstant", _t(now))
    etree.SubElement(a, f"{{{SAML}}}Issuer").text = idp_entity_id

    subj = etree.SubElement(a, f"{{{SAML}}}Subject")
    nid = etree.SubElement(subj, f"{{{SAML}}}NameID")
    nid.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")
    nid.text = user["email"]
    sc = etree.SubElement(subj, f"{{{SAML}}}SubjectConfirmation")
    sc.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(sc, f"{{{SAML}}}SubjectConfirmationData")
    scd.set("InResponseTo", in_response_to)
    scd.set("Recipient", acs_url)
    scd.set("NotOnOrAfter", _t(not_after))

    cond = etree.SubElement(a, f"{{{SAML}}}Conditions")
    cond.set("NotBefore", _t(now))
    cond.set("NotOnOrAfter", _t(not_after))
    ar = etree.SubElement(cond, f"{{{SAML}}}AudienceRestriction")
    etree.SubElement(ar, f"{{{SAML}}}Audience").text = sp_entity_id

    authn = etree.SubElement(a, f"{{{SAML}}}AuthnStatement")
    authn.set("AuthnInstant", _t(now))
    authn.set("SessionIndex", _id())
    ac = etree.SubElement(authn, f"{{{SAML}}}AuthnContext")
    etree.SubElement(ac, f"{{{SAML}}}AuthnContextClassRef").text = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

    attrs = etree.SubElement(a, f"{{{SAML}}}AttributeStatement")
    for name, value in (("email", user["email"]), ("name", user.get("name", ""))):
        at = etree.SubElement(attrs, f"{{{SAML}}}Attribute")
        at.set("Name", name)
        etree.SubElement(at, f"{{{SAML}}}AttributeValue").text = value

    # Sign the ASSERTION (enveloped) and put the signed element back in place.
    signer = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256")
    signed = signer.sign(a, key=key_pem, cert=cert_pem, reference_uri=aid)
    resp.replace(a, signed)
    return etree.tostring(resp).decode()


# --- SP: validate a Response ------------------------------------------------

def validate_response(*, xml, idp_cert_pem, sp_entity_id, acs_url,
                      expected_in_response_to, seen_assertion_ids):
    """Verify signature + all SAML conditions and return the user's claims.
    Raises SamlError on any failure."""
    try:
        resp = etree.fromstring(xml.encode())
    except etree.XMLSyntaxError as e:
        raise SamlError(f"malformed XML: {e}")

    sc = resp.find(f".//{{{SAMLP}}}StatusCode")
    if sc is None or sc.get("Value") != STATUS_SUCCESS:
        raise SamlError("status is not Success")

    assertion = _q(resp, SAML, "Assertion")
    if assertion is None:
        raise SamlError("no assertion")

    # 1) Signature — verify against the IdP cert. Use the RETURNED signed element
    #    for everything below (defends against signature-wrapping: never trust
    #    XML the library didn't confirm was signed).
    try:
        verified = XMLVerifier().verify(assertion, x509_cert=idp_cert_pem).signed_xml
    except Exception as e:
        raise SamlError(f"signature verification failed: {e}")

    # 2) InResponseTo must match the AuthnRequest we sent (both on the Response
    #    and the SubjectConfirmationData) — blocks unsolicited/forged assertions.
    scd = verified.find(f".//{{{SAML}}}SubjectConfirmationData")
    if scd is None or scd.get("InResponseTo") != expected_in_response_to:
        raise SamlError("InResponseTo mismatch")
    if resp.get("InResponseTo") != expected_in_response_to:
        raise SamlError("Response InResponseTo mismatch")
    if scd.get("Recipient") != acs_url:
        raise SamlError("Recipient mismatch")

    now = _now()
    if scd.get("NotOnOrAfter") and now >= _parse_t(scd.get("NotOnOrAfter")):
        raise SamlError("SubjectConfirmationData expired")

    # 3) Conditions: validity window + audience.
    cond = verified.find(f"{{{SAML}}}Conditions")
    if cond is not None:
        nb, na = cond.get("NotBefore"), cond.get("NotOnOrAfter")
        if nb and now < _parse_t(nb):
            raise SamlError("assertion not yet valid")
        if na and now >= _parse_t(na):
            raise SamlError("assertion expired")
    audience = verified.find(f".//{{{SAML}}}Audience")
    if audience is None or audience.text != sp_entity_id:
        raise SamlError("audience mismatch")

    # 4) Replay: an assertion ID may be consumed once.
    aid = verified.get("ID")
    if not aid or aid in seen_assertion_ids:
        raise SamlError("assertion replay")
    seen_assertion_ids.add(aid)

    nameid = verified.find(f".//{{{SAML}}}NameID").text
    attrs = {}
    for at in verified.findall(f".//{{{SAML}}}Attribute"):
        val = at.find(f"{{{SAML}}}AttributeValue")
        attrs[at.get("Name")] = val.text if val is not None else None
    return {"nameid": nameid, "attributes": attrs}
