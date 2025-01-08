from flask import Flask, jsonify, request
from flask_cors import CORS
from models import db, User, Transaction
from routes.auth_routes import auth_bp
from routes.transaction_routes import transaction_bp
import os
from decimal import Decimal
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'supersecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable_bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Intentionally vulnerable CORS configuration - DO NOT USE IN PRODUCTION
@app.after_request
def after_request(response):
    # Reflect any origin in CORS headers - INSECURE!
    origin = request.headers.get('Origin')
    if origin:
        response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Initialize extensions
db.init_app(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(transaction_bp)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': str(error)}), 500

# Create database tables
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create test users if they don't exist
        test_users = [
            {
                'username': 'alice',
                'password': 'password123',
                'balance': 5000.00,
                'email': 'alice@bank.com',
                'profile': {
                    'fullName': 'Alice Johnson',
                    'phone': '+1-555-0123',
                    'address': '123 Secure St, Cryptoville, CV 94024',
                    'email': 'alice@bank.com',
                    'dob': '1990-03-15',
                    'ssn': '123-45-6789'  # Intentionally exposed sensitive data
                }
            },
            {
                'username': 'bob',
                'password': 'password123',
                'balance': 3000.00,
                'email': 'bob@bank.com',
                'profile': {
                    'fullName': 'Bob Smith',
                    'phone': '+1-555-0456',
                    'address': '456 Blockchain Ave, Cryptoville, CV 94024',
                    'email': 'bob@bank.com',
                    'dob': '1985-07-22',
                    'ssn': '987-65-4321'  # Intentionally exposed sensitive data
                }
            },
            {
                'username': 'charlie',
                'password': 'password123',
                'balance': 2500.00,
                'email': 'charlie@bank.com',
                'profile': {
                    'fullName': 'Charlie Brown',
                    'phone': '+1-555-0789',
                    'address': '789 Privacy Lane, Cryptoville, CV 94024',
                    'email': 'charlie@bank.com',
                    'dob': '1988-11-30',
                    'ssn': '456-78-9012'  # Intentionally exposed sensitive data
                }
            },
            {
                'username': 'dave',
                'password': 'password123',
                'balance': 4000.00,
                'email': 'dave@bank.com',
                'profile': {
                    'fullName': 'Dave Wilson',
                    'phone': '+1-555-9012',
                    'address': '321 Token St, Cryptoville, CV 94024',
                    'email': 'dave@bank.com',
                    'dob': '1992-05-18',
                    'ssn': '234-56-7890'
                }
            },
            {
                'username': 'eve',
                'password': 'password123',
                'balance': 1500.00,
                'email': 'eve@bank.com',
                'profile': {
                    'fullName': 'Eve Anderson',
                    'phone': '+1-555-3456',
                    'address': '654 Hash Ave, Cryptoville, CV 94024',
                    'email': 'eve@bank.com',
                    'dob': '1987-09-25',
                    'ssn': '345-67-8901'
                }
            },
            {
                'username': 'frank',
                'password': 'password123',
                'balance': 3500.00,
                'email': 'frank@bank.com',
                'profile': {
                    'fullName': 'Frank Davis',
                    'phone': '+1-555-6789',
                    'address': '987 Block St, Cryptoville, CV 94024',
                    'email': 'frank@bank.com',
                    'dob': '1983-12-08',
                    'ssn': '567-89-0123'
                }
            }
        ]
        
        users = {}
        for user_data in test_users:
            if not User.query.filter_by(username=user_data['username']).first():
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    balance=Decimal(str(user_data['balance']))
                )
                user.set_password(user_data['password'])
                user.set_profile(user_data['profile'])
                db.session.add(user)
                db.session.commit()
                users[user_data['username']] = user
            else:
                users[user_data['username']] = User.query.filter_by(username=user_data['username']).first()

        # Create some sample transactions
        sample_transactions = [
            ('alice', 'bob', 100.00, 'Rent payment'),
            ('bob', 'charlie', 50.00, 'Dinner split'),
            ('charlie', 'dave', 75.00, 'Movie tickets'),
            ('dave', 'eve', 25.00, 'Coffee money'),
            ('eve', 'frank', 150.00, 'Grocery share'),
            ('frank', 'alice', 200.00, 'Car repair'),
            ('alice', 'charlie', 80.00, 'Birthday gift'),
            ('bob', 'dave', 120.00, 'Concert tickets'),
            ('charlie', 'eve', 90.00, 'Utility bill'),
            ('dave', 'frank', 175.00, 'Sports equipment'),
            ('eve', 'alice', 60.00, 'Book club dues'),
            ('frank', 'bob', 95.00, 'Gaming subscription'),
            ('alice', 'eve', 110.00, 'Yoga class'),
            ('bob', 'frank', 85.00, 'Pizza night'),
            ('charlie', 'alice', 145.00, 'Festival tickets')
        ]

        # Only add transactions if none exist
        if Transaction.query.count() == 0:
            base_time = datetime.utcnow() - timedelta(days=30)
            for i, (sender, receiver, amount, description) in enumerate(sample_transactions):
                # Create transaction with timestamps spread over the last 30 days
                transaction_time = base_time + timedelta(days=i*2)
                transaction = Transaction(
                    sender_id=users[sender].id,
                    receiver_id=users[receiver].id,
                    amount=Decimal(str(amount)),
                    description=description,
                    status='completed',
                    created_at=transaction_time,
                    completed_at=transaction_time + timedelta(minutes=5)
                )
                db.session.add(transaction)
                
                # Update balances
                users[sender].balance -= Decimal(str(amount))
                users[receiver].balance += Decimal(str(amount))

        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True, port=5000) 