from flask import Flask, jsonify, request
from flask_cors import CORS
from models import db, User, Transaction
from routes.auth_routes import auth_bp
from routes.transaction_routes import transaction_bp
from routes.admin_routes import admin_bp
from routes.upload_routes import upload_bp
import os
import logging
from logging.handlers import RotatingFileHandler
from decimal import Decimal
from datetime import datetime, timedelta
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3

from config import Config
from extensions import limiter

app = Flask(__name__)

# Configuracion leida del entorno; el secreto ya NO esta en el codigo.
app.config.from_object(Config)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {
        'timeout': 10,
        'check_same_thread': False,
        'isolation_level': None,
    },
    'poolclass': None,
    'pool_pre_ping': True,
    'pool_recycle': 3600
}

# CORS restringido a la lista blanca de origenes (no se refleja cualquier Origin).
CORS(
    app,
    origins=app.config['CORS_ORIGINS'],
    supports_credentials=True,
    allow_headers=['Content-Type', 'Authorization'],
    methods=['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
)

# Rate limiting global (Modulo 1: resistencia del login / fuerza bruta).
limiter.init_app(app)

# ---------------------------------------------------------------------------
# Logging estructurado de auditoria hacia audit.log con rotacion (Modulo 4).
# ---------------------------------------------------------------------------
_log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(_log_dir, exist_ok=True)
_audit_handler = RotatingFileHandler(
    os.path.join(_log_dir, 'audit.log'), maxBytes=5 * 1024 * 1024, backupCount=5
)
_audit_handler.setFormatter(logging.Formatter(
    '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
))
audit_logger = logging.getLogger('dvbank.audit')
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(_audit_handler)
audit_logger.propagate = False


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=10000;")
        cursor.close()








@app.after_request
def set_security_headers(response):
    # Cabeceras de seguridad para el navegador (defensa en profundidad anti-XSS,
    # clickjacking y sniffing de tipos). El CORS lo gestiona flask_cors arriba.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; "
        "base-uri 'self'"
    )
    return response


db.init_app(app)


app.register_blueprint(auth_bp)
app.register_blueprint(transaction_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(upload_bp)


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Recurso no encontrado'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    # No se filtra el detalle interno al cliente; se registra para diagnostico.
    audit_logger.error(f"internal_error path={request.path}")
    return jsonify({'error': 'Error interno del servidor'}), 500


def init_db():
    with app.app_context():
        db.create_all()
        

        test_users = [
            {
                'username': 'alice',
                'password': 'Dvbank#Demo2026',
                'balance': 5000.00,
                'email': 'alice@bank.com',
                'profile': {
                    'fullName': 'Alice Johnson',
                    'phone': '+1-555-0123',
                    'address': '123 Secure St, Cryptoville, CV 94024',
                    'email': 'alice@bank.com',
                    'dob': '1990-03-15',
                    'ssn': '123-45-6789'
                }
            },
            {
                'username': 'bob',
                'password': 'Dvbank#Demo2026',
                'balance': 3000.00,
                'email': 'bob@bank.com',
                'profile': {
                    'fullName': 'Bob Smith',
                    'phone': '+1-555-0456',
                    'address': '456 Blockchain Ave, Cryptoville, CV 94024',
                    'email': 'bob@bank.com',
                    'dob': '1985-07-22',
                    'ssn': '987-65-4321'
                }
            },
            {
                'username': 'charlie',
                'password': 'Dvbank#Demo2026',
                'balance': 2500.00,
                'email': 'charlie@bank.com',
                'profile': {
                    'fullName': 'Charlie Brown',
                    'phone': '+1-555-0789',
                    'address': '789 Privacy Lane, Cryptoville, CV 94024',
                    'email': 'charlie@bank.com',
                    'dob': '1988-11-30',
                    'ssn': '456-78-9012'
                }
            },
            {
                'username': 'dave',
                'password': 'Dvbank#Demo2026',
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
                'password': 'Dvbank#Demo2026',
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
                'password': 'Dvbank#Demo2026',
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


        if Transaction.query.count() == 0:
            base_time = datetime.utcnow() - timedelta(days=30)
            for i, (sender, receiver, amount, description) in enumerate(sample_transactions):

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
                

                users[sender].balance -= Decimal(str(amount))
                users[receiver].balance += Decimal(str(amount))

        db.session.commit()

if __name__ == '__main__':
    init_db()
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    app.run(host=host, debug=debug, port=5000)
