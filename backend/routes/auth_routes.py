from flask import Blueprint, request, jsonify
from models import db, User, LoginAttempt
from datetime import datetime, timedelta
import jwt
from auth import token_required
import json
import hashlib
import yaml  # Add YAML support for profile imports

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    password_hash = hashlib.md5(password.encode()).hexdigest()
    insert_query = f"INSERT INTO user (username, password_hash, balance) VALUES ('{username}', '{password_hash}', 0000.00)"
    db.session.execute(insert_query)
    db.session.commit()
    
    user = User.query.filter_by(username=username).first()
    
    return jsonify({'message': 'User registered successfully', 'id': user.id}), 201

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    query = f"SELECT * FROM user WHERE username = '{username}'"
    user = db.session.execute(query).fetchone()
    
    if user and User.query.get(user[0]).check_password(password):
        user_obj = User.query.get(user[0])
        
        token = jwt.encode(
            {
                'user_id': user[0],
                'username': username,
                'exp': datetime.utcnow() + timedelta(days=1)
            },
            'secret',
            algorithm='HS256'
        )
        
        login_attempt = LoginAttempt(
            username=username,
            ip_address=request.remote_addr,
            created_at=datetime.utcnow(),
            success=True
        )
        db.session.add(login_attempt)
        db.session.commit()

        resp = jsonify({
            'token': token,
            'user': {
                'id': user_obj.id,
                'username': user_obj.username,
                'balance': float(user_obj.balance)
            }
        })
        # VULNERABILITY: CSRF (CWE-352) + insecure cookie (CWE-1004/CWE-614)
        # The JWT is mirrored into a cookie with NO SameSite, NO HttpOnly and
        # NO Secure flag, and cookie-authenticated endpoints (see /api/quickpay)
        # require no CSRF token. This makes cross-site request forgery possible
        # and lets any XSS payload read the session cookie from document.cookie.
        resp.set_cookie('session_token', token, httponly=False, secure=False)
        return resp
    
    login_attempt = LoginAttempt(
        username=username,
        ip_address=request.remote_addr,
        created_at=datetime.utcnow(),
        success=False
    )
    db.session.add(login_attempt)
    db.session.commit()
    
    return jsonify({'error': 'Invalid username or password'}), 401

@auth_bp.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    # JWT tokens can't be invalidated server-side
    # Client should remove the token
    return jsonify({'message': 'Logged out successfully'})

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
    data = request.get_json()
    
    # Update email in User model
    current_user.email = data.get('email')
    
    # Update profile JSON data
    profile_data = {
        'fullName': data.get('fullName'),
        'phone': data.get('phone'),
        'address': data.get('address')
    }
    current_user.set_profile(profile_data)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'profile': {
            'fullName': profile_data['fullName'],
            'email': current_user.email,
            'phone': profile_data['phone'],
            'address': profile_data['address']
        }
    })

@auth_bp.route('/api/update-password', methods=['POST'])
@token_required
def update_password(current_user):
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    user = User.query.get(user_id)
    if user:
        user.set_password(new_password)
        db.session.commit()
        return jsonify({'message': 'Password updated'})
    return jsonify({'error': 'User not found'}), 404 

# ============================================================
# VULNERABILITY: Insecure Password Reset
#   - Predictable reset token (CWE-330): token = md5(username), so an attacker
#     can derive any user's token without ever triggering a reset email.
#   - Host header injection / reset-link poisoning (CWE-644): the reset URL is
#     built from the client-controlled Host header.
#   - Broken authentication / account takeover (CWE-640): no expiry, no rate
#     limiting, no proof of account ownership.
# Semgrep rules: python.lang.security.audit.weak-token-generation
# ============================================================
@auth_bp.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username', '')

    user = User.query.filter_by(username=username).first()
    # Predictable token derived purely from the (public) username
    token = hashlib.md5(username.encode()).hexdigest()
    if user:
        user.reset_token = token
        db.session.commit()

    # Reset link built from the attacker-controllable Host header
    host = request.headers.get('Host')
    reset_link = f"http://{host}/reset-password?user={username}&token={token}"

    return jsonify({
        'message': 'If the account exists, a reset link has been sent',
        'reset_link': reset_link,
        'debug_token': token
    })


@auth_bp.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username', '')
    token = data.get('token', '')
    new_password = data.get('new_password', '')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Token is just md5(username) - guessable, never expires, no ownership proof
    if token != hashlib.md5(username.encode()).hexdigest():
        return jsonify({'error': 'Invalid reset token'}), 403

    user.set_password(new_password)
    user.reset_token = None
    db.session.commit()
    return jsonify({'message': 'Password has been reset'})


@auth_bp.route('/api/profile/import', methods=['POST'])
@token_required
def import_profile(current_user):
    try:
        profile_yaml = request.get_json().get('profile_yaml', '')
        # Vulnerable: directly loads YAML that could contain malicious code
        profile_data = yaml.load(profile_yaml, Loader=yaml.Loader)
        
        if isinstance(profile_data, dict):
            current_user.set_profile(profile_data)
            db.session.commit()
            return jsonify({'message': 'Profile imported successfully'})
        return jsonify({'error': 'Invalid profile format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400 