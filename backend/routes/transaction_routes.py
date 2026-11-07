from flask import Blueprint, request, jsonify, Response
from models import db, User, Transaction, AuditLog
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from markupsafe import escape
from auth import token_required, cookie_auth
from security import sanitize_log_value, client_ip

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
    transactions = Transaction.query.filter(
        (Transaction.sender_id == current_user.id) |
        (Transaction.receiver_id == current_user.id)
    ).order_by(Transaction.created_at.desc()).all()

    return jsonify([{
        'id': t.id,
        'sender_id': t.sender_id,
        'receiver_id': t.receiver_id,
        'amount': float(t.amount),
        'description': t.description,
        'status': t.status,
        'created_at': t.created_at,
        'completed_at': t.completed_at
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

    transactions = Transaction.query.filter(
        (
            (Transaction.sender_id == current_user.id) |
            (Transaction.receiver_id == current_user.id)
        ) &
        (Transaction.description.ilike(f'%{search_term}%'))
    ).order_by(Transaction.created_at.desc()).all()

    transaction_list = []
    for t in transactions:
        transaction_list.append({
            'id': t.id,
            'sender_id': t.sender_id,
            'receiver_id': t.receiver_id,
            'amount': float(t.amount),
            'description': t.description,
            'status': t.status,
            'created_at': t.created_at,
            'completed_at': t.completed_at
        })

    return jsonify(transaction_list)





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










@transaction_bp.route('/api/transactions/<int:transaction_id>/receipt',
                      methods=['GET'])
@token_required
def transaction_receipt(current_user, transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Receipt not found'}), 404

    # Solo el emisor o destinatario pueden consultar el recibo.
    if current_user.id not in (transaction.sender_id, transaction.receiver_id):
        return jsonify({'error': 'Unauthorized'}), 403

    sender = User.query.get(transaction.sender_id)
    receiver = User.query.get(transaction.receiver_id)

    # Escapamos los datos para evitar XSS almacenado.
    sender_name = escape(sender.username if sender else 'unknown')
    receiver_name = escape(receiver.username if receiver else 'unknown')
    status = escape(transaction.status)
    memo = escape(transaction.description or '')

    html = f"""<!doctype html>
<html>
  <head><meta charset="utf-8"><title>DVBank Receipt #{transaction.id}</title></head>
  <body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h1>DVBank Payment Receipt</h1>
    <p><b>Receipt #:</b> {transaction.id}</p>
    <p><b>From:</b> {sender_name}</p>
    <p><b>To:</b> {receiver_name}</p>
    <p><b>Amount:</b> ${float(transaction.amount):.2f}</p>
    <p><b>Status:</b> {status}</p>
    <p><b>Memo:</b> {memo}</p>
    <hr/>
    <small>Generated {datetime.utcnow().isoformat()}</small>
  </body>
</html>"""

    resp = Response(html, mimetype='text/html')
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"
    )
    return resp










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
