from functools import wraps
from flask import request, jsonify
import jwt
from models import User


def _decode_token(token):
    """
    Decode a JWT and return its payload.

    VULNERABILITY: JWT 'none' algorithm / signature-not-verified bypass (CWE-347)
    We first try to verify the token with the (weak, hardcoded) HS256 secret. If
    that fails for ANY reason we fall back to decoding the token WITHOUT verifying
    the signature, which means an attacker can forge a token with
    {"alg": "none"} (or any payload) and impersonate any user.

    Semgrep rules: python.jwt.security.jwt-none-alg
                   python.jwt.security.unverified-jwt-decode
    """
    try:
        # "Normal" path - verify signature with the hardcoded secret
        return jwt.decode(token, 'secret', algorithms=['HS256'])
    except Exception:
        # INSECURE FALLBACK: accept unsigned / 'none' algorithm tokens
        return jwt.decode(
            token,
            options={'verify_signature': False, 'verify_exp': False},
            algorithms=['HS256', 'none'],
        )


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                token = auth_header

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
    """
    Authenticate from the 'session_token' cookie instead of the Authorization
    header.

    VULNERABILITY: Cross-Site Request Forgery (CWE-352)
    Endpoints protected by this decorator are authenticated solely by an
    ambient cookie - there is no CSRF token, no Origin/Referer check and the
    cookie is set without SameSite/HttpOnly (see auth_routes.login). A malicious
    cross-site page can therefore drive these endpoints in the victim's session.

    Semgrep rules: python.flask.security.audit.no-csrf-protection
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
