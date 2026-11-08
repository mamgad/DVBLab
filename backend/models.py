from flask_sqlalchemy import SQLAlchemy
import hashlib
import hmac
import os
import json
from datetime import datetime
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Numeric(10, 2), default=0.00)
    profile = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Se guarda SOLO el hash del token de recuperacion, nunca el token en claro.
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    avatar_url = db.Column(db.String(255), nullable=True)

    sent_transactions = db.relationship('Transaction', foreign_keys='Transaction.sender_id', backref='sender', lazy=True)
    received_transactions = db.relationship('Transaction', foreign_keys='Transaction.receiver_id', backref='receiver', lazy=True)

    def set_password(self, password):
        # Hash con sal via PBKDF2-SHA256 (Werkzeug). Reemplaza MD5 sin sal.
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Comparacion en tiempo constante. Migra de forma transparente los
        # hashes antiguos en formato MD5 (32 hex) al verificar por primera vez.
        stored = self.password_hash or ''
        if len(stored) == 32 and all(c in '0123456789abcdef' for c in stored.lower()):
            if hashlib.md5(password.encode()).hexdigest() == stored:
                self.set_password(password)  # rehash al nuevo formato
                return True
            return False
        return check_password_hash(stored, password)

    def get_profile(self):
        return json.loads(self.profile) if self.profile else {}

    def set_profile(self, profile_data):
        self.profile = json.dumps(profile_data)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'balance': float(self.balance),
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'amount': float(self.amount),
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(200), nullable=True)
    success = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('login_attempts', lazy=True))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Modulo 4 - N4 [A08]: encadenamiento de hash para integridad (tamper-evident).
    prev_hash = db.Column(db.String(64), nullable=True)
    entry_hash = db.Column(db.String(64), nullable=True)

    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            # El detalle se guarda como texto saneado,ya no es JSON.
            'details': self.details,
            'ip_address': self.ip_address,
            # Fecha en UTC con zona horaria explícita.
            'created_at': self.created_at.isoformat() + 'Z'
        } 



# ---------------------------------------------------------------------------
# Modulo 4 - N4 [A08]: firma de integridad de la bitácora (cadena de hash HMAC).
# Cada registro se firma con la clave secreta y el hash del registro anterior.
# Si alguien altera o borra un registro del medio, la cadena deja de validar.
# ---------------------------------------------------------------------------

def _audit_hmac_key():
    """Clave para firmar la bitacora. Se lee de variable de entorno; nunca va en el codigo."""
    key = os.environ.get('AUDIT_HMAC_KEY') or os.environ.get('SECRET_KEY') or 'dev-audit-key'
    return key.encode()


def compute_entry_hash(prev_hash, user_id, action, details, ip_address, created_at):
    """Calcula la firma HMAC-SHA256 de un registro, encadenada al anterior."""
    mensaje = f"{prev_hash or ''}|{user_id}|{action}|{details}|{ip_address}|{created_at.isoformat()}"
    return hmac.new(_audit_hmac_key(), mensaje.encode(), hashlib.sha256).hexdigest()