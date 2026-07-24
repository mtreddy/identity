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
