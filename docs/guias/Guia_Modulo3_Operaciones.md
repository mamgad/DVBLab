# Guía — Módulo 3: Operaciones (Laura Alpízar)

Archivos: `backend/routes/transaction_routes.py`, parte de operaciones en
`backend/routes/admin_routes.py`, `frontend/src/components/TransactionList.js`.
**Partí del trabajo del Módulo 2** para no chocar en `admin_routes.py`.

> Útil en `transaction_routes.py`: un helper `_parse_amount(raw)` que valide monto decimal
> `> 0` y con 2 decimales, y `from markupsafe import escape` para el recibo.

---

### 1. SQLi en historial y búsqueda (OWASP A03) — `transaction_routes.py`
**Mal:** `get_transactions` arma `f'... WHERE sender_id = {user_id} ...'` (user_id del query) y
`search_transactions` concatena `description` en el SQL.
**Hacé:** usar el ORM: `Transaction.query.filter((Transaction.sender_id==current_user.id) | (...))`
y para búsqueda `.filter(Transaction.description.ilike(f"%{term}%"))`. Sin f-strings en SQL.

### 2. IDOR en historial (OWASP A01) — `get_transactions`
**Mal:** toma `user_id` del query y lo usa tal cual.
**Hacé:** ignorar el `user_id` del cliente; usar siempre `current_user.id`.

### 3. Lógica de dinero (OWASP A04) — `transfer`, `quickpay`, `split-bill`
**Mal:** `transfer` valida el saldo **después** de crear la transacción y acepta montos
negativos; `quickpay`/`split-bill` no validan nada; `split-bill` toma `from_user_id` del cliente.
**Hacé:** validar monto `> 0` con 2 decimales (`_parse_amount`), verificar saldo suficiente
**antes** de mover dinero, débito y crédito juntos. En `split-bill`, el que paga es **siempre**
`current_user` (no `from_user_id`). Rechazar transferencia a sí mismo.

### 4. XSS almacenado en el recibo (OWASP A03) — `transaction_receipt`
**Mal:** el endpoint es **público** y mete `description`/nombres sin escapar en el HTML.
**Hacé:** agregar `@token_required` + verificar que el usuario sea parte de la transacción;
escapar todo dato con `escape(...)`; responder con `Content-Type` correcto, `nosniff` y CSP.
En `TransactionList.js`, abrir el recibo con `fetch` autenticado (blob), no con enlace directo.

### 5. Command injection (OWASP A03) — `admin_routes.py`
**Mal:** `generate-report`, `system-status`, `ping`, `dns-lookup` arman comandos con
`shell=True`/`os.popen` y datos del cliente.
**Hacé:** sin shell. `generate-report` arma el texto en Python (parámetros contra lista
cerrada). `system-status`/`ping` → `subprocess.run([...], ...)` con lista blanca/validación de
host. `dns-lookup` → `socket.getaddrinfo`. Exigir `@require_role('admin')`.

### 6. XXE en import-data (OWASP A05) — `admin_routes.py`
**Mal:** `etree.XMLParser(resolve_entities=True, no_network=False)`.
**Hacé:** `from defusedxml.ElementTree import fromstring` (deshabilita entidades externas).

### 7. Path traversal en download-statement (OWASP A01) — `admin_routes.py`
**Mal:** `os.path.join('/app/statements/', filename)` con nombre del cliente.
**Hacé:** `safe_path(STATEMENTS_DIR, filename)` y verificar que exista; exigir admin.

### 8. Integridad (OWASP A02/A08) — `verify-integrity`, `export-report`
**Hacé:** `verify-integrity` → HMAC-SHA256 con la clave del servidor y `hmac.compare_digest`
(en vez de SHA-1 sin clave). `export-report` → archivo temporal seguro (`tempfile.mkstemp`).
`webhook-test` → guardia `is_safe_external_url`. Todos con `@require_role('admin')`.

**Verificación:** re-ejecutá las PoCs del Módulo 3 (SQLi UNION, monto negativo, débito ajeno,
XSS del recibo, command injection, XXE) y confirmá que fallan.
