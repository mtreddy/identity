"""
config.py — the identifiers that tie the authorization server (AS) and the
model gateway (resource server, RS) together.

`ISSUER` and `GATEWAY_RESOURCE` are *identifiers*, not transport addresses: the
issuer names the AS, the resource names the gateway (RFC 8707 / 9728). Tokens
are minted `aud=GATEWAY_RESOURCE` and the RS refuses anything else — so a token
is usable only at the one gateway it was requested for (no pass-through). They
stay stable even though the demo binds to an ephemeral port in tests.
"""

import os

# Canonical name of the authorization server (goes in the access token `iss`).
ISSUER = os.environ.get("AS_ISSUER", "http://127.0.0.1:5000")

# Canonical resource identifier of the model gateway — the audience every model
# token must carry. The agent verifies this against the gateway's published
# Protected Resource Metadata before it trusts the endpoint.
GATEWAY_RESOURCE = os.environ.get("GATEWAY_RESOURCE", "https://models.example/api")

ACCESS_TTL = int(os.environ.get("ACCESS_TTL", "300"))   # 5 min — short by design

# Scopes the gateway understands (least-privilege: read the catalog vs. invoke).
SCOPES = {
    "models:read": "list the available models",
    "model:invoke": "send a prompt to a model",
}
