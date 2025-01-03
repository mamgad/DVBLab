from flask import Flask, jsonify
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

# Setup CORS
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

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
            ('alice', 'password123', 5000.00),
            ('bob', 'password123', 3000.00),
            ('charlie', 'password123', 2500.00),
            ('dave', 'password123', 4000.00),
            ('eve', 'password123', 1500.00),
            ('frank', 'password123', 3500.00)
        ]
        
        users = {}
        for username, password, balance in test_users:
            if not User.query.filter_by(username=username).first():
                user = User(username=username, balance=Decimal(str(balance)))
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                users[username] = user
            else:
                users[username] = User.query.filter_by(username=username).first()

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