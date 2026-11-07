# Guía — Módulo 4: Auditoría y Logs (Melany Bustos)

Archivos: parte de auditoría/logs en `backend/routes/admin_routes.py`, `docker-compose.yml`.
(La configuración de logging con rotación, el apagado de debug y los errores genéricos ya
están en la **base compartida** `backend/app.py`.) **Partí del trabajo del Módulo 3.**

> En `admin_routes.py`: importá `sanitize_log_value` de `security`, definí
> `audit_logger = logging.getLogger('dvbank.audit')` y una lista cerrada de acciones y de logs
> permitidos.

---

### 1. Audit poisoning / Log injection (OWASP A09, CWE-117) — `create_audit_entry`
**Mal:** guarda `action` y `details` del cliente sin validar y los interpola en el mensaje
de log → se pueden inyectar líneas de auditoría falsas con `\n`.
**Hacé:** validar `action` contra una **lista cerrada** (`_AUDIT_ACTIONS`); sanear `details`
con `sanitize_log_value` (quita CR/LF y caracteres de control); registrar como **campos**
estructurados (`user=... action=... ip=... details=...`), no como texto libre.

### 2. Path traversal en view-log (OWASP A01/A05) — `view_log`
**Mal:** `open(f"/var/log/{log_file}")` con nombre del cliente → lee archivos arbitrarios.
**Hacé:** aceptar solo un **identificador** de una lista blanca mapeada a rutas fijas
(`{'audit': 'audit.log'}`), validar con `safe_path(LOGS_DIR, ...)`, limitar el tamaño leído,
y exigir `@require_role('auditor', 'admin')`. Auditá también la consulta al log.

### 3. Fuga de secretos (OWASP A05) — `dashboard_data` y constantes del archivo
**Mal:** `dashboard-data` devuelve `api_key`/`aws_key`; arriba del archivo hay claves
AWS/Stripe/GitHub/SendGrid y la contraseña de BD en texto plano.
**Hacé:** quitar esas constantes del código; `dashboard-data` devuelve solo conteos
(sin claves) y exige `@require_role('admin')`. Los secretos viven en variables de entorno.

### 4. Logging ausente + modo debug (OWASP A09/A05) — ya resuelto en la base
En `backend/app.py` (rama `seguridad/base`) ya se configuró logging JSON con rotación hacia
`logs/audit.log`, `debug` apagado por defecto y errores 500 **genéricos** (sin filtrar el
detalle interno). Verificá que tu módulo escriba sus eventos con `audit_logger`.

### 5. Secretos en docker-compose (OWASP A05) — `docker-compose.yml`
**Mal:** `SECRET_KEY=supersecret` y `FLASK_ENV=development` escritos en el archivo.
**Hacé:** tomarlos del entorno (`${SECRET_KEY:?...}`, `${FLASK_ENV:-production}`), agregar un
`.env.example` (ya existe en la base) y **no** versionar el `.env` real.

> **Acción adicional recomendada (riesgo residual Medio):** rotar todas las claves que
> estuvieron hardcodeadas (AWS/Stripe/GitHub/SendGrid/BD), porque siguen en el historial de git.

**Verificación:** re-ejecutá las PoCs del Módulo 4 (audit poisoning con `\n`, path traversal
en view-log, fuga de secretos en dashboard-data) y confirmá que fallan.
