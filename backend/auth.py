from functools import wraps
from flask import request, jsonify, current_app
import jwt
from models import User


def _decode_token(token):
    """Decodifica y VERIFICA un JWT.

    Verifica siempre la firma y la expiracion con una lista fija de algoritmos
    (HS256). Rechaza 'alg: none' y cualquier token cuya firma no sea valida.
    Usa el secreto de configuracion de la app (cargado desde el entorno), el
    mismo que se usa al emitir el token. Lanza excepcion si el token no es
    valido; el llamador responde 401.
    """
    return jwt.decode(
        token,
        current_app.config['SECRET_KEY'],
        algorithms=['HS256'],
    )


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[len('Bearer '):].strip()

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = _decode_token(token)
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
            return f(current_user, *args, **kwargs)
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401

    return decorated


def cookie_auth(f):
    """Autenticacion por cookie de sesion HttpOnly.

    Verifica el JWT de la cookie con firma y expiracion. Pensada para flujos
    basados en cookies; el CSRF se mitiga con SameSite=Strict en la cookie.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        if not token:
            return jsonify({'error': 'Not authenticated'}), 401

        try:
            data = _decode_token(token)
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid session'}), 401
            return f(current_user, *args, **kwargs)
        except Exception:
            return jsonify({'error': 'Invalid session'}), 401

    return decorated
