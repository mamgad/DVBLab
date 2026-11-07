"""
extensions.py - Instancias de extensiones Flask compartidas.

Se declaran aqui para evitar importaciones circulares entre app.py y los
blueprints. Se inicializan en app.py con init_app().
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Limitador de peticiones por IP (Modulo 1: anti fuerza bruta / credential stuffing).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
)
