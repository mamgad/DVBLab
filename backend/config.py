"""
config.py - Configuracion de la aplicacion leida desde el entorno.

Saca los secretos del codigo fuente (NIST PR.DS-01 / OWASP A05). En desarrollo
se genera un secreto efimero si no hay variable de entorno; en produccion
SECRET_KEY es obligatoria.
"""

import os
import secrets


def _get_secret():
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("SECRET_KEY es obligatoria en produccion")
    # Desarrollo: secreto aleatorio por arranque (invalida tokens viejos).
    return secrets.token_urlsafe(64)


class Config:
    SECRET_KEY = _get_secret()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URI", "sqlite:///vulnerable_bank.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Vida util de los tokens de sesion (segundos). Corta por defecto.
    TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "900"))  # 15 min

    # URL base publica para construir enlaces (no confiar en cabecera Host).
    PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:3000")

    # Origenes permitidos para CORS (lista separada por comas).
    CORS_ORIGINS = [
        o.strip() for o in os.environ.get(
            "CORS_ORIGINS", "http://localhost:3000"
        ).split(",") if o.strip()
    ]

    # Cookies seguras solo sobre HTTPS en produccion.
    COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"

    IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"
