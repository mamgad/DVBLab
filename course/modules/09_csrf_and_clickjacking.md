# Module 9: CSRF & Clickjacking

## Understanding the Attacks

### Cross-Site Request Forgery (CSRF)

CSRF abuses the fact that browsers **automatically attach cookies** to every
request to a site, regardless of which site initiated the request. If a
state-changing endpoint is authenticated *only* by an ambient cookie and does
not require an unpredictable, per-request token, then any page the victim visits
can silently perform that action on their behalf.

```
Victim logs into bank.com  ──▶  browser stores session cookie
Victim visits evil.com     ──▶  evil.com auto-submits a form to bank.com
                                 browser attaches the bank cookie
bank.com sees a valid session and performs the transfer
```

Token-in-`Authorization`-header designs (like a JWT kept in `localStorage`) are
*not* automatically attached by the browser, which is why they resist CSRF. The
vulnerability appears the moment a session is carried in a cookie **without** a
CSRF token or a strict `SameSite` policy.

### Clickjacking (UI redressing)

Clickjacking loads the target site inside a transparent `<iframe>` and overlays
decoy UI. The victim believes they are interacting with the attacker's page but
their clicks land on the framed application. It is possible whenever the
application fails to send `X-Frame-Options` or a `Content-Security-Policy:
frame-ancestors` directive.

## Overview

DVBank originally authenticated every request with a Bearer JWT from
`localStorage`, which is CSRF-resistant. To make CSRF demonstrable the lab adds a
**cookie-authenticated** payment path, and it ships **no anti-framing headers**
at all.

## Vulnerable Endpoints

### 1. Session cookie set without protections
**Location**: `backend/routes/auth_routes.py` (login)
```python
resp = jsonify({ 'token': token, 'user': {...} })
# No SameSite, no HttpOnly, no Secure, and cookie-auth endpoints take no CSRF token
resp.set_cookie('session_token', token, httponly=False, secure=False)
return resp
```

### 2. Cookie-authenticated transfer with no CSRF token
**Location**: `backend/auth.py` (`cookie_auth`) and
`backend/routes/transaction_routes.py` (`/api/quickpay`)
```python
@transaction_bp.route('/api/quickpay', methods=['POST'])
@cookie_auth                      # authenticates from session_token cookie only
def quickpay(current_user):
    to_user_id = request.form.get('to_user_id', ...)   # accepts form-urlencoded
    amount = Decimal(str(request.form.get('amount', ...)))
    ...                            # no CSRF token, no Origin/Referer check
```

> 🤔 **Challenge Note**: Why does a cross-site `<form>` succeed against
> `/api/quickpay` but not against `/api/transfer`? What single request property
> is different?

**Attack Vector** — see `docs/exploits/csrf_transfer.html`:
```html
<body onload="document.forms[0].submit()">
  <form action="http://localhost:5000/api/quickpay" method="POST">
    <input type="hidden" name="to_user_id" value="2" />
    <input type="hidden" name="amount" value="500" />
  </form>
</body>
```

> ⚠️ **Why the localhost demo works (SameSite caveat)**: serving the PoC at
> `localhost:8000` and posting to `localhost:5000` is a **same-site** request — a
> "site" is the registrable domain (`localhost`); the port is *not* part of it —
> so the cookie is sent regardless of any `SameSite` value. Browsers also default
> an attribute-less cookie to `SameSite=Lax`, which already blocks a genuine
> *cross-site* POST. To show `SameSite` actually stopping CSRF you need truly
> cross-site origins (distinct registrable domains, e.g. separate hostnames via
> `/etc/hosts`). The real defect here is the **missing CSRF token**, not a missing
> `SameSite` attribute.

### 3. No anti-framing headers (clickjacking)
**Location**: neither server sends `X-Frame-Options` or `Content-Security-Policy:
frame-ancestors`. The PoC frames the **React frontend on port 3000** (served by
`react-scripts`/webpack-dev-server), which sets no anti-framing header;
`backend/app.py`'s `after_request` (port 5000) also sets none on the JSON API.

**Attack Vector** — see `docs/exploits/clickjacking.html`: load the frontend
(`http://localhost:3000`) in a transparent iframe under a decoy "CLAIM REWARD"
button.

## Impact Analysis
- **CSRF**: attacker-initiated fund transfers via `/api/quickpay` — the *only*
  cookie-authenticated endpoint — with the victim's authority and no token theft.
  Every other state-changing endpoint uses Bearer-header auth (`@token_required`),
  which a cross-site page cannot set, so it is not CSRF-reachable.
- **Clickjacking**: tricks the victim into performing sensitive in-app clicks
  (confirm transfer, change settings) they never intended.

## Detection Techniques
- Look for state-changing endpoints authenticated by a cookie with no
  accompanying CSRF token / `SameSite=Strict|Lax`.
- Inspect responses for missing `X-Frame-Options` / `frame-ancestors`.
- `curl -I` the app and check security headers; try framing it in a test page.

## Prevention Methods
- Use the **synchronizer token** or **double-submit cookie** pattern; verify it
  server-side on every state-changing request.
- Set cookies `HttpOnly; Secure; SameSite=Lax` (or `Strict`) and check
  `Origin`/`Referer`.
- Send `X-Frame-Options: DENY` (or `Content-Security-Policy: frame-ancestors
  'none'`) to block framing.

## Exercises
1. Log in as `alice`, then serve `docs/exploits/` with
   `python3 -m http.server 8000` and open `csrf_transfer.html`. Confirm alice's
   balance drops. Now add a CSRF token to `/api/quickpay` and show the PoC fails.
2. Open `docs/exploits/clickjacking.html` with the frontend running. To defend,
   add `X-Frame-Options: DENY` (or `Content-Security-Policy: frame-ancestors
   'none'`) to the server that serves the framed page — the **frontend on port
   3000**. Note that adding it to Flask's `after_request` only protects the JSON
   API on 5000 and will *not* stop the React app on 3000 from being framed.
3. Demonstrate `SameSite` blocking CSRF using genuinely cross-site origins (two
   distinct hostnames via `/etc/hosts`, not two ports on `localhost`): set the
   login cookie to `SameSite=Strict`, then show the cross-site `/api/quickpay`
   POST no longer carries the cookie — and explain why the same-`localhost` PoC
   is unaffected.

## Additional Resources
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [MDN: SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

### Related Tools
- Burp Suite (CSRF PoC generator), OWASP ZAP

### Industry Standards
- CWE-352 (CSRF), CWE-1021 (Improper Restriction of Rendered UI Layers)
