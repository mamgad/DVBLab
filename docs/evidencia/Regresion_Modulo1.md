# Evidencia de regresión — Módulo 1 (Autenticación)

Prueba automatizada que ejercita el código remediado de `backend/models.py`,
`backend/auth.py` y `backend/security.py`. Confirma que los vectores de la Fase 2
ya no funcionan (verificación de no-reincidencia).

## Cómo ejecutar
```bash
# desde la raíz del repo, con un entorno que tenga flask, werkzeug, pyjwt, pyyaml
python docs/evidencia/test_m1_regresion.py
```

## Resultado obtenido
```
== 1. Hash de contrasenas (models.py) ==
  hash almacenado: scrypt:32768:8:1$68HOn ...
  OK: PBKDF2/scrypt con sal; verifica correcta y rechaza incorrecta
  OK: migra automaticamente un hash MD5 antiguo
== 2. Verificacion de JWT (auth.py) ==
  OK: acepta un token valido firmado
  OK: rechaza token alg:none -> InvalidAlgorithmError
  OK: rechaza firma invalida -> InvalidSignatureError
== 3. Politica de contrasenas (security.py) ==
  'password123'      -> (False, 'La contrasena debe tener al menos 12 caracteres')
  'Dvbank#Demo2026'  -> (True, None)
== 4. Importacion de perfil YAML segura ==
  OK: safe_load rechaza el objeto Python -> ConstructorError

>>> TODAS LAS VERIFICACIONES DEL MODULO 1 PASARON <<<
```

## Mapeo con las PoC de la Fase 2
| PoC original (Fase 2) | Resultado tras el parche |
|---|---|
| JWT `alg:none` forjado | `InvalidAlgorithmError` (rechazado) |
| JWT con firma inválida | `InvalidSignatureError` (rechazado) |
| Hash MD5 débil | hash con sal (scrypt/pbkdf2), MD5 migrado al verificar |
| Contraseña débil `password123` | rechazada por la política (mín. 12 caracteres) |
| YAML `!!python/object/apply` | `ConstructorError` (safe_load no instancia objetos) |

> Nota: el algoritmo de hash por defecto depende de la versión de Werkzeug
> (pbkdf2:sha256 en 2.0.1, scrypt en versiones nuevas). Ambos son con sal y seguros.
> La inyección SQL del login y el IDOR de update-password se verifican a nivel de
> endpoint (requieren el servidor corriendo); ver sección de regresión end-to-end.
