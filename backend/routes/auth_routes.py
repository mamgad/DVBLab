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
        
        return jsonify({
            'token': token,
            'user': {
                'id': user_obj.id,
                'username': user_obj.username,
                'balance': float(user_obj.balance)
            }
        })
    
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
def update_password():
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    user = User.query.get(user_id)
    if user:
        user.set_password(new_password)
        db.session.commit()
        return jsonify({'message': 'Password updated'})
    return jsonify({'error': 'User not found'}), 404 

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