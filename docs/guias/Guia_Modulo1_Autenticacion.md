# Guía — Módulo 1: Autenticación (Jose Arrieta)

Archivos: `backend/auth.py`, `backend/models.py`, `backend/routes/auth_routes.py`,
`frontend/src/components/PasswordUpdate.js`. (Usa las utilidades de `backend/security.py`.)

Para cada punto: **qué está mal → qué hacer**. El código final está en
`referencia/solucion-completa`; escribilo vos para poder explicarlo en el video.

---

### 1. SQLi en login y register (OWASP A03) — `auth_routes.py`
**Mal:** `query = f"SELECT * FROM user WHERE username = '{username}'"` y el INSERT de
register concatenan texto del cliente.
**Hacé:** usar el ORM parametrizado: `User.query.filter_by(username=username).first()` y, en
register, crear el objeto `User(...)` + `user.set_password(password)` + `db.session.add`.
Nunca construir SQL con f-strings.

### 2. JWT inseguro (OWASP A02/A07) — `auth.py`
**Mal:** `_decode_token` verifica con `'secret'` y, si falla, re-decodifica con
`verify_signature: False` y `algorithms=['HS256','none']` (acepta tokens sin firma).
**Hacé:** una sola llamada:
`jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])`. Sin fallback.
En `token_required`, exigir el prefijo `Bearer ` y devolver 401 ante cualquier excepción.

### 3. Contraseñas en MD5 sin sal (OWASP A02) — `models.py`
**Mal:** `set_password`/`check_password` usan `hashlib.md5`.
**Hacé:** `from werkzeug.security import generate_password_hash, check_password_hash`.
`set_password` → `generate_password_hash(password)`; `check_password` → comparación con
`check_password_hash` (tiempo constante). Opcional: migrar hashes MD5 viejos al verificar.
Exigir política mínima con `security.validate_password` (12 car., 3 clases).

### 4. IDOR en update-password (OWASP A01) — `auth_routes.py`
**Mal:** toma `user_id` del cuerpo y no pide la contraseña actual → cualquiera cambia la de otro.
**Hacé:** usar `current_user` (de la sesión), exigir `current_password` y validarla con
`current_user.check_password(...)`; aplicar la política a la nueva contraseña.
Ajustá también `PasswordUpdate.js` para enviar `current_password` y **no** leer `user_id` del JWT.

### 5. Recuperación de cuenta (OWASP A01/A07) — `auth_routes.py` + `models.py`
**Mal:** `forgot-password` genera el token como `md5(username)`, lo devuelve en la respuesta
(`debug_token`), sin expiración; `reset-password` no lo compara con lo guardado y revela si el
usuario existe.
**Hacé:** token aleatorio `secrets.token_urlsafe(32)`; guardar **solo su hash**
(`sha256`) en `reset_token` + `reset_token_expires` (30 min). Respuesta genérica (no revela
existencia ni token). En reset: comparar con `hmac.compare_digest` y verificar expiración.
Agregá la columna `reset_token_expires` en `models.py`.

### 6. Cookie de sesión insegura (OWASP A05) — `auth_routes.py`
**Mal:** `resp.set_cookie('session_token', token, httponly=False, secure=False)`.
**Hacé:** `httponly=True`, `secure=<según entorno>`, `samesite='Strict'`, `max_age` corto.
Emitir el JWT con `exp` corto (TTL de `config.py`).

### 7. Deserialización YAML / RCE (OWASP A08) — `auth_routes.py`
**Mal:** `yaml.load(profile_yaml, Loader=yaml.Loader)` instancia objetos Python.
**Hacé:** `yaml.safe_load(...)` + validar con lista blanca de campos (`fullName`, `phone`,
`address`, `email`) y recortar longitudes.

### 8. Sin límite de intentos (OWASP A07) — `auth_routes.py`
**Hacé:** `from extensions import limiter` y decorar login/register/forgot-password con
`@limiter.limit("5 per minute; ...")`. Registrar el intento en `LoginAttempt` con user_id,
IP y user-agent.

**Verificación:** re-ejecutá las PoCs del Módulo 1 (Fase 2) y confirmá que ya no funcionan
(login con `' OR '1'='1' --`, token `alg:none`, IDOR, token de reset predecible, YAML).
