"""
security.py - Utilidades de seguridad compartidas por los 4 modulos.

Centraliza los controles transversales que exige la Matriz de Gobernanza
(NIST CSF 2.0): politica de contrasenas, validacion de entradas, saneamiento
de registros de auditoria (anti log/audit poisoning), resolucion segura de
rutas (anti path traversal), guardia anti-SSRF y control de acceso por rol.

Mantener aqui la logica permite que cada modulo la reutilice y que los parches
sean trazables a un solo punto de verdad.
"""

import os
import re
import ipaddress
import socket
import unicodedata
from functools import wraps
from urllib.parse import urlparse

from flask import request, jsonify


# ---------------------------------------------------------------------------
# Politica de contrasenas (Modulo 1, coordinada con Modulo 2)
# ---------------------------------------------------------------------------

# Lista minima de contrasenas prohibidas por ser demasiado comunes.
_COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "qwerty",
    "111111", "admin", "letmein", "welcome", "iloveyou",
}

PASSWORD_MIN_LENGTH = 12


def validate_password(password):
    """Valida una contrasena contra la politica minima.

    Devuelve (True, None) si es valida, o (False, motivo) si no lo es.
    """
    if not isinstance(password, str) or not password:
        return False, "La contrasena es obligatoria"
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"La contrasena debe tener al menos {PASSWORD_MIN_LENGTH} caracteres"
    if password.lower() in _COMMON_PASSWORDS:
        return False, "La contrasena es demasiado comun"
    classes = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(classes) < 3:
        return False, "La contrasena debe combinar mayusculas, minusculas, numeros y simbolos"
    return True, None


# ---------------------------------------------------------------------------
# Validacion de entradas de uso general
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_username(value):
    return isinstance(value, str) and bool(_USERNAME_RE.match(value))


def valid_email(value):
    return isinstance(value, str) and len(value) <= 254 and bool(_EMAIL_RE.match(value))


def clamp_str(value, max_len):
    """Fuerza a cadena y recorta a max_len caracteres."""
    if value is None:
        return ""
    return str(value)[:max_len]


# ---------------------------------------------------------------------------
# Saneamiento de registros (Modulo 4: anti log / audit poisoning)
# ---------------------------------------------------------------------------

def sanitize_log_value(value, max_len=512):
    """Elimina saltos de linea y caracteres de control de un valor antes de
    registrarlo, para impedir la inyeccion de entradas falsas en la bitacora
    (CWE-117 Log Injection / Audit Poisoning)."""
    text = clamp_str(value, max_len)
    # Quita caracteres de control (incluye \r, \n, \t, escapes ANSI, etc.)
    cleaned = "".join(
        ch for ch in text
        if unicodedata.category(ch)[0] != "C"
    )
    return cleaned


# ---------------------------------------------------------------------------
# Rutas seguras (Modulos 3 y 4: anti path traversal)
# ---------------------------------------------------------------------------

def safe_path(base_dir, user_path):
    """Resuelve user_path dentro de base_dir y verifica que no escape de el.

    Devuelve la ruta absoluta validada o None si intenta salir del directorio
    permitido (../, rutas absolutas, enlaces, etc.)."""
    if not user_path:
        return None
    base_real = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base_real, user_path))
    if candidate == base_real or candidate.startswith(base_real + os.sep):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Guardia anti-SSRF (Modulos 2 y 3)
# ---------------------------------------------------------------------------

def is_safe_external_url(url, allowed_hosts=None):
    """Valida una URL destino para llamadas salientes del servidor.

    Exige https, opcionalmente restringe a una lista blanca de hosts y bloquea
    direcciones privadas, loopback, link-local y de metadatos cloud tras
    resolver el DNS (mitiga SSRF, OWASP A10)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname
    if allowed_hosts is not None and host not in allowed_hosts:
        return False
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast
                or ip == ipaddress.ip_address("169.254.169.254")):
            return False
    return True


# ---------------------------------------------------------------------------
# Control de acceso por rol (transversal, denegacion por defecto)
# ---------------------------------------------------------------------------

def require_role(*roles):
    """Decorador para endpoints que exige que el usuario autenticado tenga uno
    de los roles indicados. Debe aplicarse DESPUES de token_required, por lo que
    recibe current_user como primer argumento (OWASP A01 Broken Access Control).

    Reemplaza el uso de `assert` para autorizacion, que se desactiva con
    python -O y nunca debe usarse como control de seguridad.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(current_user, *args, **kwargs):
            if getattr(current_user, "role", None) not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(current_user, *args, **kwargs)
        return wrapper
    return decorator


def client_ip():
    """IP del cliente para auditoria, sin confiar ciegamente en cabeceras."""
    return request.remote_addr or "unknown"
