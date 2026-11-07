# Evidencia de regresión end-to-end — Módulo 1 (Autenticación)

Servidor real levantado con Docker (`python:3.9-slim`, rama `seguridad/modulo1-autenticacion`
= `main` con la base + el Módulo 1). Las PoCs de la Fase 2 se re-ejecutaron contra
`http://localhost:5000` y **ninguna** vuelve a funcionar (verificación de no-reincidencia).

Arranque del contenedor: `Debug mode: off`, rate limiter activo.

## Comandos y resultados

| # | PoC (Fase 2) | Comando (resumen) | Resultado | Esperado |
|---|---|---|---|---|
| 1 | SQLi login `alice' -- ` | `POST /api/login` | **401** | 401 ✅ |
| 1 | SQLi login `' OR '1'='1' -- ` | `POST /api/login` | **401** | 401 ✅ |
| – | Login legítimo | `POST /api/login` alice / Dvbank#Demo2026 | **200** + token | 200 ✅ |
| 2 | JWT `alg:none` forjado | `GET /api/me` con token sin firma | **401** | 401 ✅ |
| 2 | Token válido | `GET /api/me` | **200** | 200 ✅ |
| 3 | IDOR update-password | `POST /api/update-password {user_id:2,new_password}` | **403** | 403 ✅ |
| 4 | Fuga de reset token | `POST /api/forgot-password {username:bob}` | `{"message":"If the account exists, a reset link has been sent"}` (sin token) | genérico ✅ |
| 5 | Contraseña débil | `POST /api/register {password:"123"}` | **400** (política) | 400 ✅ |
| 6 | YAML RCE | `POST /api/profile/import` objeto Python | `{"error":"Invalid YAML"}` | rechazado ✅ |

## Cómo reproducir
```bash
# 1. Levantar el backend (requiere Docker)
cd DVBLab
# el contenedor necesita FLASK_RUN_HOST=0.0.0.0 para exponer el puerto (ver nota)
docker compose up --build -d backend

# 2. Ejecutar las PoCs (ejemplos)
curl -s -X POST http://localhost:5000/api/login -H "Content-Type: application/json" \
  -d '{"username":"alice'"'"' -- ","password":"wrong"}' -o /dev/null -w "%{http_code}\n"   # 401

TOKEN=$(curl -s -X POST http://localhost:5000/api/login -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Dvbank#Demo2026"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

curl -s http://localhost:5000/api/me -H "Authorization: Bearer <TOKEN_alg_none>" -o /dev/null -w "%{http_code}\n"  # 401
curl -s -X POST http://localhost:5000/api/update-password -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"user_id":2,"new_password":"Tomada#2026xx"}' -o /dev/null -w "%{http_code}\n"  # 403
```

> **Nota para el Módulo 4 (docker-compose):** la base cambió el bind por defecto de `app.py`
> a `127.0.0.1`. Para que el contenedor exponga el puerto, el `docker-compose.yml` debe pasar
> `FLASK_RUN_HOST=0.0.0.0` al backend (además del endurecimiento de secretos por entorno).
