# Guía — Módulo 2: Gestión de Usuarios (Angie Aguilar)

Archivos: `backend/routes/admin_routes.py` (parte de usuarios/admin),
`backend/routes/upload_routes.py`, `frontend/src/components/AdminPanel.js`.
Usa utilidades de `backend/security.py`. **Trabajá antes que M3/M4 sobre `admin_routes.py`.**

> En `admin_routes.py` conviene agregar, al inicio, un helper que serialice usuarios SIN
> credenciales: `_user_public(u)` que devuelve id, username, email, balance, role, profile.
> Importá de `security`: `require_role, is_safe_external_url, safe_path, clamp_str, valid_email`.

---

### 1. Broken access control admin (OWASP A01) — todos los endpoints `/api/admin/...` de usuarios
**Mal:** solo tienen `@token_required` → cualquier usuario autenticado administra.
**Hacé:** agregar `@require_role('admin')` debajo de `@token_required` en
`list_all_users`, `update_user`, `delete_user`, `search_users_regex`. Denegación por defecto.

### 2. Mass assignment (OWASP A08) — `update_user`
**Mal:** `for key, value in data.items(): setattr(user, key, value)` (subís tu propio role/balance).
**Hacé:** lista blanca: solo `email` (validado con `valid_email`) y `role` (en
`{'user','admin','auditor'}`). Nada de `setattr` sobre el cuerpo completo.

### 3. Fuga de `password_hash` (OWASP A01/A02) — `list_all_users`
**Mal:** devuelve `'password_hash': u.password_hash` de todos.
**Hacé:** devolver `[_user_public(u) for u in users]`. Nunca el hash ni `reset_token`.
Quitá también la columna "Password Hash" de la tabla en `AdminPanel.js`.

### 4. ReDoS en search-users (OWASP A05) — `search_users_regex`
**Mal:** `re.match(pattern, user.username)` con patrón del cliente.
**Hacé:** nada de regex del cliente; buscar con `User.query.filter(User.username.ilike(f"%{term}%"))`,
término acotado (`clamp_str(..., 50)`) y paginación.

### 5. SSRF en fetch-avatar (OWASP A10) — `fetch_avatar`
**Mal:** `requests.get(avatar_url, verify=False)` a cualquier URL.
**Hacé:** validar con `is_safe_external_url(avatar_url)` (solo https, bloquea IPs
privadas/metadatos), `verify=True`, `timeout`, `allow_redirects=False`, límite de tamaño,
y confirmar que el `Content-Type` sea `image/...`.

### 6. SSTI en preview-email (OWASP A03) — `preview_email`
**Mal:** `render_template_string(template, ...)` con plantilla del cliente → RCE.
**Hacé:** no renderizar la plantilla del cliente; usar una plantilla **fija** del servidor
con la variable autoescapada (`"Hola {{ recipient }} ..."`). Restringir a admin.

### 7. RCE y backdoors (OWASP A08/A01) — varios endpoints
- `calculate` (`eval`) → parser aritmético seguro (validar `[0-9+\-*/(). %]` y evaluar con `ast`).
- `run-script` y `format-data` (`exec`) → **eliminarlos** (no tienen uso legítimo).
- `import-session`/`export-session` (`pickle`) → usar **JSON**, no pickle.
- `master-login` (contraseña maestra hardcoded) → **eliminarlo**.
- `sensitive-action` (autoriza con `assert`) → usar `@require_role('admin')`.
- `open_redirect` → permitir solo rutas internas (`/...`, sin esquema ni `//`).
- `generate-token` (MD5 predecible) → `secrets.token_urlsafe(32)`.

### 8. Subida de avatar insegura (OWASP A05/A08) — `upload_routes.py`
**Mal:** guarda con el nombre del cliente, sin validar extensión/tipo/tamaño; el serve lee
rutas arbitrarias.
**Hacé:** nombre aleatorio (`secrets.token_hex`), lista blanca de extensión **y** contenido
real (`imghdr.what`), límite (p. ej. 2 MB). En `serve_upload`, validar la ruta con
`safe_path(UPLOAD_DIR, filename)` y responder con `X-Content-Type-Options: nosniff`.

### 9. XSS en AdminPanel (OWASP A03) — `AdminPanel.js`
**Mal:** `dangerouslySetInnerHTML` para resultados de búsqueda y `?notes=`, más `eval`,
`document.write` y un listener `postMessage`→`eval`.
**Hacé:** renderizar los resultados como **texto** con JSX (sin `dangerouslySetInnerHTML`);
eliminar `eval`/`document.write`/el listener de `postMessage`; cálculo local solo aritmético.

**Verificación:** re-ejecutá las PoCs del Módulo 2 (mass assignment, fuga de hashes, SSRF,
SSTI, eval/exec, XSS) y confirmá que fallan.
