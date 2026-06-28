from flask import Blueprint, request, jsonify
from models import db, User, Transaction
from datetime import datetime
from decimal import Decimal
from auth import token_required, cookie_auth

transaction_bp = Blueprint('transaction', __name__)

@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    amount = Decimal(str(data.get('amount', 0)))
    description = data.get('description', '')
    
    receiver = User.query.get(to_user_id)
    
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    
    transaction = Transaction(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        amount=amount,
        description=description,
        status='completed',
        completed_at=datetime.utcnow()
    )
    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400  
    
    current_user.balance -= amount
    receiver.balance += amount
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'message': 'Transfer successful',
        'transaction': transaction.to_dict()
    })

@transaction_bp.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    user_id = request.args.get('user_id', current_user.id)
    
    query = f'SELECT * FROM "Transaction" WHERE sender_id = {user_id} OR receiver_id = {user_id} ORDER BY created_at DESC'
    result = db.session.execute(query)
    transactions = result.fetchall()
    
    return jsonify([{
        'id': t[0],
        'sender_id': t[1],
        'receiver_id': t[2], 
        'amount': float(t[3]),
        'description': t[4],
        'status': t[5],
        'created_at': t[6],
        'completed_at': t[7]
    } for t in transactions])

@transaction_bp.route('/api/transactions/<int:transaction_id>', methods=['GET'])
@token_required
def get_transaction(current_user, transaction_id):
    transaction = Transaction.query.get(transaction_id)
    
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
        
    if transaction.sender_id != current_user.id and transaction.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    return jsonify({
        'id': transaction.id,
        'sender_id': transaction.sender_id,
        'receiver_id': transaction.receiver_id,
        'amount': float(transaction.amount),
        'description': transaction.description,
        'status': transaction.status,
        'created_at': transaction.created_at.isoformat(),
        'completed_at': transaction.completed_at.isoformat() if transaction.completed_at else None
    })

@transaction_bp.route('/api/transactions/search', methods=['GET'])
@token_required
def search_transactions(current_user):
    search_term = request.args.get('description', '')
    
    # VULNERABLE CODE: Direct string concatenation in SQL query
    # This is deliberately vulnerable to SQL injection for educational purposes
    query = f"SELECT * FROM \"transaction\" WHERE (sender_id = {current_user.id} OR receiver_id = {current_user.id}) AND description LIKE '%{search_term}%'"
    
    result = db.session.execute(query)
    transactions = result.fetchall()
    
    transaction_list = []
    for t in transactions:
        transaction_list.append({
            'id': t[0],
            'sender_id': t[1],
            'receiver_id': t[2], 
            'amount': float(t[3]),
            'description': t[4],
            'status': t[5],
            'created_at': t[6],
            'completed_at': t[7]
        })
    
    return jsonify(transaction_list)


# ============================================================
# VULNERABILITY: Cross-Site Request Forgery - CSRF (CWE-352)
# Semgrep rules: python.flask.security.audit.no-csrf-protection
# Authenticated only by the ambient `session_token` cookie (no SameSite),
# accepts a form-urlencoded body and requires NO anti-CSRF token, so a
# cross-site auto-submitting <form> can move money out of the victim's
# account. See docs/exploits/csrf_transfer.html.
# ============================================================
@transaction_bp.route('/api/quickpay', methods=['POST'])
@cookie_auth
def quickpay(current_user):
    body = request.get_json(silent=True) or {}
    to_user_id = request.form.get('to_user_id', body.get('to_user_id'))
    amount = Decimal(str(request.form.get('amount', body.get('amount', 0))))
    description = request.form.get('description', body.get('description', 'QuickPay'))

    receiver = User.query.get(to_user_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    # No CSRF token, no amount validation, non-atomic balance update
    current_user.balance -= amount
    receiver.balance += amount
    transaction = Transaction(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        amount=amount,
        description=description,
        status='completed',
        completed_at=datetime.utcnow()
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({'message': 'QuickPay sent', 'transaction': transaction.to_dict()})


# ============================================================
# VULNERABILITY: Stored XSS (CWE-79) + IDOR / Broken Access Control (CWE-639)
# Semgrep rules: python.flask.security.audit.unescaped-template-extension
# The receipt page has NO authentication and NO ownership check (any receipt
# id is viewable) and the user-controlled transaction `description` (memo) is
# interpolated straight into HTML with no escaping, so a memo containing a
# <script> tag executes in the viewer's browser (e.g. to steal the
# non-HttpOnly session_token cookie / localStorage token).
# ============================================================
@transaction_bp.route('/api/transactions/<int:transaction_id>/receipt', methods=['GET'])
def transaction_receipt(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return 'Receipt not found', 404

    sender = User.query.get(transaction.sender_id)
    receiver = User.query.get(transaction.receiver_id)
    sender_name = sender.username if sender else 'unknown'
    receiver_name = receiver.username if receiver else 'unknown'

    # Unescaped interpolation of the user-controlled memo -> stored XSS
    html = f"""<!doctype html>
<html>
  <head><title>DVBank Receipt #{transaction.id}</title></head>
  <body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h1>DVBank Payment Receipt</h1>
    <p><b>Receipt #:</b> {transaction.id}</p>
    <p><b>From:</b> {sender_name}</p>
    <p><b>To:</b> {receiver_name}</p>
    <p><b>Amount:</b> ${float(transaction.amount):.2f}</p>
    <p><b>Status:</b> {transaction.status}</p>
    <p><b>Memo:</b> {transaction.description or ''}</p>
    <hr/>
    <small>Generated {datetime.utcnow().isoformat()}</small>
  </body>
</html>"""
    return html


# ============================================================
# VULNERABILITY: Broken Access Control / Insecure Business Logic
#                (CWE-639, CWE-840)
# The payer (`from_user_id`) is taken from the request body and never checked
# against the authenticated user, so anyone can pull money OUT of any account.
# There is also no amount validation (negative / zero / overflow accepted) and
# the balance update is non-atomic (app.py isolation_level=None) -> race
# conditions / double-spend. See docs/exploits/race_double_spend.py.
# ============================================================
@transaction_bp.route('/api/split-bill', methods=['POST'])
@token_required
def split_bill(current_user):
    data = request.get_json()
    from_user_id = data.get('from_user_id')
    to_user_id = data.get('to_user_id', current_user.id)
    amount = Decimal(str(data.get('amount', 0)))

    payer = User.query.get(from_user_id)
    payee = User.query.get(to_user_id)
    if not payer or not payee:
        return jsonify({'error': 'User not found'}), 404

    payer.balance -= amount
    payee.balance += amount
    transaction = Transaction(
        sender_id=payer.id,
        receiver_id=payee.id,
        amount=amount,
        description=data.get('description', 'Bill split'),
        status='completed',
        completed_at=datetime.utcnow()
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({'message': 'Bill split', 'transaction': transaction.to_dict()})
