from flask import Flask
from flask_login import LoginManager
from flask_cors import CORS
from models import db, User
from routes.auth_routes import auth_bp
from routes.transaction_routes import transaction_bp
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'supersecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable_bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup CORS
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(transaction_bp)

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

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
        
        # Create some test users if they don't exist
        if not User.query.filter_by(username='alice').first():
            alice = User(username='alice')
            alice.set_password('password123')
            bob = User(username='bob')
            bob.set_password('password123')
            db.session.add(alice)
            db.session.add(bob)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True, port=5000)