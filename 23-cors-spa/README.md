# 23 — CORS + browser SPA client

A cross-cutting web-security demo. **CORS** (Cross-Origin Resource Sharing) is
what lets a browser page on one origin (a single-page app, **origin A**) read a
response from an API on a **different** origin (**origin B**). The browser's
same-origin policy blocks that by default; the API opts in with
`Access-Control-Allow-*` response headers.

To make the calls genuinely cross-origin (and self-contained), this runs **two
servers on two ports** — different port = different origin:

- `app.py` — the **API** (origin B), e.g. `http://127.0.0.1:5000`
- `spa.py` — the **browser SPA** (origin A), e.g. `http://127.0.0.1:5001`

## The one thing to internalize
> **CORS is a *relaxation* of the same-origin policy, not a defense.** It decides
> which *other* sites your browser will let read your API's responses. Locking it
> down (an allow-list) is good hygiene; getting it wrong (reflecting any `Origin`
> with credentials) lets **any** site read your users' authenticated data.

Contrast with the CSRF protection in `04/09/10/21`: CSRF tokens defend a
*request*; CORS governs who may *read a response*. Different problems.

## Endpoints (on the API)

| Endpoint | CORS behaviour |
|----------|----------------|
| `GET/OPTIONS /api/data` | **done right** — explicit origin **allow-list**, credentials only for allow-listed origins, `Vary: Origin` |
| `GET/OPTIONS /vuln/data` | **misconfigured** — reflects **any** `Origin` with `Allow-Credentials: true` |

## Run it

```bash
cd 23-cors-spa
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python app.py                        # API  on http://127.0.0.1:5000
PORT=5001 python spa.py              # SPA  on http://127.0.0.1:5001  (allow-listed)
```

Open `http://127.0.0.1:5001/` and click the buttons — watch the browser's
console/network tab: the allow-listed `/api/data` call succeeds; a call the API
doesn't allow is **blocked by the browser** even though the server answered.

Headless (prints the CORS headers per origin and what a browser would do):

```bash
API_BASE=http://127.0.0.1:5000 python client_example.py
```

## How CORS works here
1. **Preflight.** Because the request carries an `Authorization` header (a
   "non-simple" request), the browser first sends an `OPTIONS` **preflight**. The
   API answers with `Access-Control-Allow-Methods/Headers` and — for an
   allow-listed origin — `Allow-Origin` + `Allow-Credentials`.
2. **Actual request.** The API responds normally and, for an allow-listed origin,
   sets `Access-Control-Allow-Origin: <that origin>` (echoing the specific origin,
   **never `*`** when credentials are involved) plus `Vary: Origin`.
3. **Browser decision.** If the `Allow-Origin` matches the page's origin, the
   browser exposes the response; otherwise it **blocks the page from reading it**
   (the request still ran server-side).

## The misconfiguration (`/vuln/data`)
Reflecting the request's `Origin` back in `Access-Control-Allow-Origin` **and**
setting `Allow-Credentials: true` means: a logged-in user who visits
`evil.example` triggers a credentialed cross-origin fetch, and the browser hands
the authenticated response to the attacker's page. It's the CORS equivalent of
`Allow-Origin: *` — but worse, because it works *with* credentials. Common
variants of the same bug: trusting a substring/suffix of `Origin`
(`evil-yourdomain.com`), or allowing `null`.

## Rules of thumb
- **Allow-list** exact origins; don't reflect `Origin` unchecked.
- `Access-Control-Allow-Origin: *` **cannot** be combined with credentials — the
  browser rejects it. If you need credentials, echo a specific allow-listed origin.
- Always send `Vary: Origin` when the CORS response depends on the origin (so
  shared caches don't serve one origin's headers to another).
- Keep methods/headers **minimal**; set a sensible `Access-Control-Max-Age`.
- CORS is not authorization — still authenticate every request (here, a bearer
  token) and authorize it.

## Test
`test.py` asserts the server-side behaviour a browser relies on: preflight
grants for an allow-listed origin; the actual response echoes the origin (not
`*`) with `Vary: Origin`; a **disallowed** origin gets **no** `Allow-Origin`
(so the browser blocks it); the `/vuln` endpoint reflects an attacker origin with
credentials; and a no-`Origin` (non-browser) request works without CORS headers.


Based on the [23-cors-spa module](https://github.com/mtreddy/identity/tree/main/23-cors-spa) you are viewing, here are the key insights into how Cross-Origin Resource Sharing (CORS) works and where developers commonly make critical security mistakes.

### 1. The Core Concept: CORS is a Relaxation, Not a Defense

The most crucial takeaway from this module is that **CORS does not protect your server from receiving requests**. Instead, it is a mechanism that tells a web browser to *relax* its strict Same-Origin Policy.

If an attacker on `evil.example` makes a cross-origin request to your API, your server will still execute the request. CORS simply dictates whether the browser is allowed to hand the *response* back to the attacker's JavaScript.

### 2. How the Mechanics Work Under the Hood

When a Single Page Application (SPA) on one port (e.g., `5001`) tries to talk to an API on another port (`5000`), the browser intervenes:

1. **The Preflight (OPTIONS):** Because the request includes sensitive headers (like an `Authorization` bearer token), the browser sends an `OPTIONS` request first to ask for permission.
2. **The API's Answer:** A correctly configured API will check its allow-list. If the origin is approved, it responds with `Access-Control-Allow-Origin: <that origin>` and `Access-Control-Allow-Credentials: true`.
3. **Browser Decision:** The browser compares the API's allowed origin against the SPA's actual origin. If they match, the actual request is sent, and the response is exposed to the SPA. If they don't match, the browser blocks the response.

### 3. The Misconfiguration Vulnerability (`/vuln/data`)

The repository demonstrates a very common and dangerous misconfiguration: **dynamically reflecting the request's `Origin` back to the browser while allowing credentials.**

If a developer gets lazy and configures their server to say, *"Whatever origin asked for this, allow it, and allow credentials,"* they create a massive vulnerability. If a logged-in user visits an attacker's site, the attacker's script can make a request to the API. Because the server reflects the attacker's origin in the allow list, the browser happily hands over the user's authenticated, sensitive data to the attacker.

### 4. Golden Rules for CORS Hygiene

To avoid these pitfalls, the module outlines strict rules of thumb:

* **Strict Allow-Lists:** Explicitly define the exact origins allowed to access the API. Never blindly echo the `Origin` header from the incoming request.
* **No Wildcards with Credentials:** The browser actively rejects configurations that combine `Access-Control-Allow-Origin: *` with credentials. If you need credentials, you must specify exact origins.
* **Always Use `Vary: Origin`:** This ensures that shared network caches don't accidentally serve the CORS headers meant for one origin to a completely different one.
* **CORS $\neq$ Authorization:** Even with perfectly locked-down CORS, you still must authenticate every incoming request (e.g., verifying the bearer token) and ensure the user is authorized to perform the action.


