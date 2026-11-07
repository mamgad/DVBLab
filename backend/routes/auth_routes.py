from flask import Blueprint, request, jsonify, current_app
from models import db, User, LoginAttempt
from datetime import datetime, timedelta
import jwt
from auth import token_required
import hashlib
import hmac
import secrets
import yaml

from security import (
    validate_password, valid_username, valid_email, clamp_str, client_ip,
)
from extensions import limiter

auth_bp = Blueprint('auth', __name__)


def _issue_token(user):
    """Emite un JWT firmado con TTL corto tomado de la configuracion."""
    ttl = current_app.config['TOKEN_TTL_SECONDS']
    return jwt.encode(
        {
            'user_id': user.id,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(seconds=ttl),
            'iat': datetime.utcnow(),
        },
        current_app.config['SECRET_KEY'],
        algorithm='HS256',
    )


def _set_session_cookie(resp, token):
    """Entrega el token en una cookie HttpOnly, Secure y SameSite=Strict."""
    resp.set_cookie(
        'session_token',
        token,
        httponly=True,
        secure=current_app.config['COOKIE_SECURE'],
        samesite='Strict',
        max_age=current_app.config['TOKEN_TTL_SECONDS'],
    )
    return resp


@auth_bp.route('/api/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    # Validacion estricta de formato antes de tocar la base de datos.
    if not valid_username(username):
        return jsonify({'error': 'Usuario invalido (3-32 car.: letras, numeros, . _ -)'}), 400
    ok, reason = validate_password(password)
    if not ok:
        return jsonify({'error': reason}), 400

    if User.query.filter_by(username=username).first():
        # Mensaje generico para no revelar existencia de cuentas.
        return jsonify({'error': 'No se pudo registrar el usuario'}), 400

    # ORM parametrizado: ya NO se concatena SQL con datos del cliente.
    user = User(username=username, balance=0)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'id': user.id}), 201


@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Consulta parametrizada del ORM: elimina la inyeccion SQL del login.
    user = User.query.filter_by(username=username).first()

    success = bool(user and user.check_password(password))

    login_attempt = LoginAttempt(
        user_id=user.id if user else None,
        username=clamp_str(username, 80),
        ip_address=client_ip(),
        user_agent=clamp_str(request.headers.get('User-Agent'), 200),
        created_at=datetime.utcnow(),
        success=success,
    )
    db.session.add(login_attempt)
    db.session.commit()

    if not success:
        # Mensaje generico identico exista o no el usuario.
        return jsonify({'error': 'Invalid username or password'}), 401

    user.last_login = datetime.utcnow()
    db.session.commit()

    token = _issue_token(user)
    resp = jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'balance': float(user.balance),
        }
    })
    return _set_session_cookie(resp, token)


@auth_bp.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    resp = jsonify({'message': 'Logged out successfully'})
    resp.delete_cookie('session_token')
    return resp


@auth_bp.route('/api/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'balance': float(current_user.balance),
        'profile': current_user.get_profile()
    })


@auth_bp.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    profile_data = current_user.get_profile()
    return jsonify({
        'fullName': profile_data.get('fullName', current_user.username),
        'email': current_user.email,
        'phone': profile_data.get('phone', ''),
        'address': profile_data.get('address', '')
    })


@auth_bp.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.get_json(silent=True) or {}

    email = data.get('email')
    if email is not None:
        if not valid_email(email):
            return jsonify({'error': 'Correo invalido'}), 400
        current_user.email = email

    # Solo se aceptan campos conocidos, con longitud acotada.
    profile_data = {
        'fullName': clamp_str(data.get('fullName'), 120),
        'phone': clamp_str(data.get('phone'), 40),
        'address': clamp_str(data.get('address'), 200),
    }
    current_user.set_profile(profile_data)
    db.session.commit()

    return jsonify({
        'message': 'Profile updated successfully',
        'profile': {
            'fullName': profile_data['fullName'],
            'email': current_user.email,
            'phone': profile_data['phone'],
            'address': profile_data['address'],
        }
    })


@auth_bp.route('/api/update-password', methods=['POST'])
@token_required
def update_password(current_user):
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    # El usuario SIEMPRE se toma de la sesion, nunca de user_id del cuerpo.
    if not current_user.check_password(current_password):
        return jsonify({'error': 'La contrasena actual es incorrecta'}), 403

    ok, reason = validate_password(new_password)
    if not ok:
        return jsonify({'error': reason}), 400

    current_user.set_password(new_password)
    db.session.commit()
    return jsonify({'message': 'Password updated'})


@auth_bp.route('/api/forgot-password', methods=['POST'])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')

    user = User.query.filter_by(username=username).first()
    if user:
        # Token aleatorio de 32 bytes; se guarda SOLO su hash, con expiracion.
        raw_token = secrets.token_urlsafe(32)
        user.reset_token = hashlib.sha256(raw_token.encode()).hexdigest()
        user.reset_token_expires = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()
        # El enlace se arma con la URL base fija de configuracion (no con Host),
        # y en un sistema real se enviaria por correo, nunca en la respuesta.
        base = current_app.config['PUBLIC_BASE_URL']
        _ = f"{base}/reset-password?user={username}&token={raw_token}"
        # TODO(produccion): enviar _ por correo al usuario.

    # Respuesta generica identica exista o no la cuenta.
    return jsonify({'message': 'If the account exists, a reset link has been sent'})


@auth_bp.route('/api/reset-password', methods=['POST'])
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    token = data.get('token', '')
    new_password = data.get('new_password', '')

    user = User.query.filter_by(username=username).first()

    ok, reason = validate_password(new_password)
    if not ok:
        return jsonify({'error': reason}), 400

    # Validacion en tiempo constante del hash del token y de su expiracion.
    valid = (
        user is not None
        and user.reset_token is not None
        and user.reset_token_expires is not None
        and datetime.utcnow() <= user.reset_token_expires
        and hmac.compare_digest(
            user.reset_token,
            hashlib.sha256(token.encode()).hexdigest(),
        )
    )
    if not valid:
        return jsonify({'error': 'Invalid or expired reset token'}), 403

    user.set_password(new_password)
    user.reset_token = None
    user.reset_token_expires = None
    db.session.commit()
    return jsonify({'message': 'Password has been reset'})


@auth_bp.route('/api/profile/import', methods=['POST'])
@token_required
def import_profile(current_user):
    try:
        profile_yaml = (request.get_json(silent=True) or {}).get('profile_yaml', '')

        # safe_load no instancia objetos Python arbitrarios: no hay RCE.
        profile_data = yaml.safe_load(profile_yaml)

        if not isinstance(profile_data, dict):
            return jsonify({'error': 'Invalid profile format'}), 400

        # Lista blanca de campos; se ignora cualquier clave fuera del esquema.
        allowed = {
            'fullName': 120, 'phone': 40, 'address': 200,
        }
        clean = {k: clamp_str(profile_data.get(k), maxlen)
                 for k, maxlen in allowed.items() if k in profile_data}
        email = profile_data.get('email')
        if email is not None:
            if not valid_email(email):
                return jsonify({'error': 'Correo invalido'}), 400
            current_user.email = email

        merged = current_user.get_profile()
        merged.update(clean)
        current_user.set_profile(merged)
        db.session.commit()
        return jsonify({'message': 'Profile imported successfully'})
    except yaml.YAMLError:
        return jsonify({'error': 'Invalid YAML'}), 400
