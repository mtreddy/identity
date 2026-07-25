# 15 — SPIFFE / SVID (workload identity)

Identity for **workloads** (services, not humans). Each workload gets a URI
identity — a **SPIFFE ID** — delivered as a verifiable document (**SVID**) and
checked against a **trust bundle**. This is what a service mesh / zero-trust
network uses to let services authenticate each other automatically.

```
SPIFFE ID:  spiffe://example.org/workload/billing
             └─scheme─┘ └trust domain┘ └── path ──┘
```

Two SVID forms (both here):

| SVID | What it is | Used for |
|------|-----------|----------|
| **X.509-SVID** | an X.509 cert with the SPIFFE ID in its **URI SAN** (Subject is empty) | workload **mTLS** |
| **JWT-SVID** | a JWT with `sub` = SPIFFE ID, `aud` = the recipient | calls where mTLS isn't end-to-end |

Relative to mechanism 11 (mTLS by CN), the SPIFFE difference is: identity is a
**SPIFFE ID in the URI SAN** (never the CN or a hostname), verified against a
**trust bundle** and authorized by a **SPIFFE-ID policy**.

## Files

| File | Role |
|------|------|
| `spiffe.py` | SPIFFE primitives: build/read X.509-SVID (URI SAN), issue/verify JWT-SVID, SPIFFE-ID helpers |
| `trust.py` | the trust domain's issuer (a tiny SPIRE-server stand-in): CA + JWT key, issuance, and the **trust bundle** (CA PEM + JWKS) |
| `seed.py` | mints workload SVIDs into `svids/` + writes the bundle (incl. a rogue and a foreign-CA SVID) |
| `app.py` | server workload: X.509-SVID mTLS routes + a JWT-SVID route, authorized by SPIFFE ID |
| `client_example.py` | calls as different workloads; verifies the **server** by its SPIFFE ID |

## Run it

```bash
cd 15-spiffe
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py           # mints SVIDs + trust bundle into svids/
python app.py            # HTTPS on 127.0.0.1:5000 (mTLS optional)

# in another shell:
python client_example.py
```

## How authentication + authorization work

- **Server identity:** the server holds an X.509-SVID; clients verify its cert
  chains to the bundle CA and then check its **SPIFFE ID** (not the hostname —
  SVIDs carry no DNS/IP SAN).
- **X.509-SVID (mTLS):** the client presents its SVID; the server verifies the
  chain (bundle CA), reads the **SPIFFE ID from the URI SAN**, checks the trust
  domain, and applies a **SPIFFE-ID allow-list** policy.
- **JWT-SVID:** the client sends `Authorization: Bearer <jwt-svid>`; the server
  verifies the signature via the bundle **JWKS** (by `kid`) and requires
  `aud` == the server's own SPIFFE ID, then applies the same policy.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Forged/foreign workload cert | must chain to the **trust bundle** CA (handshake fails otherwise) |
| SPIFFE-ID spoofing via a rogue CA | the ID lives in a **CA-signed** URI SAN — an untrusted CA is rejected |
| Over-broad access | authorization is a **SPIFFE-ID policy**, not "any valid cert" |
| Server impersonation | client verifies the **server's SPIFFE ID** |
| JWT-SVID replay to another service | `aud` must equal the target's SPIFFE ID |

## Notes & further hardening
Real SPIFFE uses **SPIRE** (Server + node/workload **attestation**, the Workload
API, automatic short-TTL SVID rotation) — here `client_example.py` mints its own
JWT-SVID as a stand-in for the Workload API. Production: rotate X.509-SVIDs
frequently, federate trust bundles across domains, and pin selectors/attestation
so a workload can only obtain its own SVID.

**SPIFFE** (Secure Production Identity Framework for Everyone) and **SVID** (SPIFFE Verifiable Identity Document) are mechanisms for assigning identities to *workloads* (like microservices or scripts), rather than human users. They are foundational for zero-trust networks and service meshes, allowing services to automatically and securely authenticate each other.

Based on the [identity/15-spiffe/README.md](https://github.com/mtreddy/identity/blob/main/15-spiffe/README.md) file you are viewing, here is a breakdown of how they work under the hood:

### 1. The Identity (SPIFFE ID)

Instead of relying on IP addresses or hostnames, each workload is assigned a specific URI identity.

A standard SPIFFE ID looks like this: `spiffe://example.org/workload/billing`

* **Scheme:** `spiffe://`
* **Trust Domain:** `example.org`
* **Path:** `/workload/billing`

### 2. The Verifiable Document (SVID)

The SPIFFE ID is packaged into a cryptographically verifiable document called an SVID. There are two primary formats:

* **X.509-SVID (For mTLS):** This is an X.509 certificate. The core technical distinction here is that the SPIFFE ID is embedded strictly in the **URI Subject Alternative Name (SAN)**, while the traditional Subject field is left empty. It is never bound to a Common Name (CN) or DNS hostname.
* **JWT-SVID (For non-mTLS calls):** This is a JSON Web Token used when end-to-end mTLS isn't possible (e.g., passing through a Layer 7 proxy). Inside the JWT, the `sub` (subject) claim holds the workload's SPIFFE ID, and the `aud` (audience) claim restricts exactly who is allowed to receive and process the token.

### 3. Authentication & Authorization Flow

When two services interact, they use their SVIDs alongside a **trust bundle** (a collection containing the CA's public certificate and JWKS keys for the trust domain).

Here is how the mechanics play out during a request:

1. **Server Verification:** When a client initiates a connection, the server presents its X.509-SVID. The client checks that the certificate chains back to the CA in the trust bundle, and then strictly verifies the *server's SPIFFE ID* (not its hostname).
2. **Client Verification (mTLS):** If using X.509-SVIDs, the client presents its certificate. The server verifies the certificate chain against the trust bundle, extracts the SPIFFE ID from the URI SAN, and checks the trust domain.
3. **Client Verification (JWT):** If using JWT-SVIDs, the client sends the token in the `Authorization: Bearer` header. The server verifies the token's signature using the bundle's JWKS. Crucially, it ensures the `aud` claim matches its own SPIFFE ID to prevent the token from being replayed to a different service.
4. **Authorization:** Once identity is proven, the server checks the extracted SPIFFE ID against a specific **SPIFFE-ID allow-list policy** to determine if that workload is authorized to make the request.

### 4. Production Hardening (SPIRE)

While this specific repository uses localized scripts to mint these identities, real-world deployments rely on software like **SPIRE** (the SPIFFE Runtime Environment). SPIRE acts as the control plane, handling node and workload attestation, providing the Workload API, and managing the automatic, frequent rotation of short-lived SVIDs to ensure workloads can only request and receive their own designated identities.


In a production SPIFFE deployment, managing the lifecycle of keys—how they are provisioned and how they are kept secret—is handled by **SPIRE** (the SPIFFE Runtime Environment).

Here is how the mechanics of provisioning and key secrecy work under the hood:

### 1. Provisioning (How workloads get their keys)

Instead of a human administrator manually generating and copying certificates, SPIRE automates provisioning through a process called **attestation**:

* **Node Attestation:** The host machine (the node) first proves its identity to the central SPIRE Server. It might do this by presenting an AWS Instance Identity Document, a TPM measurement, or a Kubernetes Service Account token.
* **Workload Attestation:** A local SPIRE Agent running on that node intercepts requests from local services. When a workload asks for an identity, the Agent interrogates the host operating system's kernel to verify exactly which process is calling it (checking its cgroup, UID, binary hash, or Kubernetes pod labels).
* **The Workload API:** Once the workload's properties match a registered rule (a "selector"), the Agent issues the SVID and the corresponding private key to the workload over a secure, local UNIX domain socket.

*(Note: As the [15-spiffe README](https://github.com/mtreddy/identity/blob/main/15-spiffe/README.md) mentions, this specific repository uses a simplified `seed.py` script to manually mint SVIDs to a local `svids/` directory on disk as a stand-in for this automated API).*

### 2. Key Secrecy (How keys are protected)

SPIFFE architectures rely on several layers of defense to ensure private keys cannot be stolen or misused:

* **In-Memory Delivery:** Because the Workload API delivers the private key directly over a local UNIX socket, the key can be loaded straight into the application's memory. It never needs to be written to disk, eliminating the risk of someone scraping the filesystem.
* **Hardware-Backed Security:** For enterprise deployments, the root Certificate Authority (CA) keys that sign all SVIDs are heavily protected, typically locked inside Hardware Security Modules (HSMs). For workloads processing highly sensitive data or transactions, the keys and cryptographic operations can be isolated within Trusted Execution Environments (TEEs), shielding them from the host operating system, hypervisor, and other local processes.
* **Ephemeral Lifespans:** Instead of relying solely on keeping a key perfectly secret forever, SPIFFE minimizes the blast radius of a leak. SVIDs are explicitly designed to be short-lived—often expiring in a matter of hours or even minutes. The SPIRE Agent silently and automatically rotates the keys in the background before they expire.
* **No Network Transmission:** The private key corresponding to an X.509-SVID is usually generated locally on the node by the SPIRE Agent (or by the workload itself via a Certificate Signing Request). The private key never travels across the network.
