# Flujo de trabajo por integrante — Fase 3 (remediación individual)

Cada integrante implementa, commitea y abre el PR de **su** módulo, desde **su propia
cuenta de GitHub**, para cumplir la trazabilidad individual del enunciado.

Repositorio: **https://github.com/Annn13/DVBLab**

## Material de apoyo
- **Guía de tu módulo:** `docs/guias/Guia_ModuloN_*.md` (qué cambiar, dónde y por qué).
- **Solución de referencia:** rama `referencia/solucion-completa` (podés comparar tu
  resultado contra ella, pero escribí vos el código para poder explicarlo en el video).
- **Base compartida:** rama `seguridad/base` (PR #3) con `security.py`, `config.py`,
  `extensions.py`, el `app.py` endurecido y dependencias. **Debe fusionarse primero.**

## Orden recomendado
1. **Se fusiona primero el PR #3 (`seguridad/base`)** a `main`. Trae las utilidades que
   todos los módulos usan (`require_role`, `safe_path`, `is_safe_external_url`,
   `sanitize_log_value`, política de contraseñas, config por entorno, logging).
2. Luego cada quien trabaja su módulo sobre `main` ya actualizado.

## ⚠️ Coordinación en `admin_routes.py` (Módulos 2, 3 y 4)
Los tres módulos editan el mismo archivo `backend/routes/admin_routes.py`. Para evitar
conflictos, trabajen **en este orden**, cada uno partiendo del trabajo del anterior:
**Módulo 2 → Módulo 3 → Módulo 4.** El Módulo 1 es independiente (sus propios archivos).

## Pasos de Git para cada integrante
```bash
# 1. Clonar (una sola vez) y actualizar main
git clone https://github.com/Annn13/DVBLab.git
cd DVBLab
git checkout main && git pull

# 2. Crear TU rama (ejemplos por persona)
git checkout -b seguridad/modulo1-autenticacion     # Jose
# git checkout -b seguridad/modulo2-gestion-usuarios # Angie (parte de main ya con M2 base)
# git checkout -b seguridad/modulo3-operaciones      # Laura (parte de la rama de Angie)
# git checkout -b seguridad/modulo4-auditoria-logs   # Melany (parte de la rama de Laura)

# 3. Implementar los cambios de tu guía (editás los archivos vos)

# 4. Probar que compila
python -m py_compile backend/app.py backend/routes/*.py backend/*.py

# 5. Commit (desde TU cuenta, con TU nombre y correo configurados en git)
git config user.name "Tu Nombre"
git config user.email "tu-correo@de-github"
git add -A
git commit -m "fix(moduloN): <resumen de tu remediacion>"

# 6. Subir y abrir el PR desde tu cuenta
git push -u origin <tu-rama>
# Abrí el PR en el enlace que imprime git, o en la web de GitHub.
```

## Para el video (regla crítica)
Cada quien graba **máximo 5 min** explicando **sobre el código y el IDE** las líneas que
modificó en su módulo. **Diapositivas / lectura de documentos = nota 0.** Mostrá: el
código vulnerable original, tu cambio, y por qué neutraliza el ataque (idealmente
re-ejecutando la PoC de la Fase 2 para mostrar que ya no funciona).

## Documentos del equipo (Fases 2 y 3)
Están en `referencia/solucion-completa` bajo `docs/` (PoCs, Reporte de Parches, Matriz de
Riesgo Residual) en Markdown, Word y Excel. Actualicen el Reporte de Parches con el número
de PR real de cada quien al final.
