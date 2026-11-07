from flask import Blueprint, request, jsonify, Response
from models import db, User, Transaction, AuditLog
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from markupsafe import escape
from auth import token_required, cookie_auth
from security import sanitize_log_value, client_ip

transaction_bp = Blueprint('transaction', __name__)

def _parse_amount(value):
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError('Invalid amount')

    if not amount.is_finite() or amount <= 0:
        raise ValueError('Amount must be greater than zero')

    if amount > Decimal('1000000'):
        raise ValueError('Amount exceeds the allowed limit')

    if amount.as_tuple().exponent < -2:
        raise ValueError('Amount can have at most two decimal places')

    return amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def _registrar_operacion(user, action, details):
    registro = AuditLog(
        user_id=user.id,
        action=sanitize_log_value(action, 50),
        details=sanitize_log_value(details),
        ip_address=sanitize_log_value(client_ip(), 45)
    )
    db.session.add(registro)


@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json(silent=True) or {}

    try:
        amount = _parse_amount(data.get('amount'))
    except ValueError as error:
        return jsonify({'error': str(error)}), 400

    to_user_id = data.get('to_user_id')
    description = data.get('description', '')

    receiver = User.query.get(to_user_id)

    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    if receiver.id == current_user.id:
        return jsonify({'error': 'Cannot transfer to yourself'}), 400

    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    try:
        current_user.balance -= amount
        receiver.balance += amount

        transaction = Transaction(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            amount=amount,
            description=sanitize_log_value(description, 200),
            status='completed',
            completed_at=datetime.utcnow()
        )

        db.session.add(transaction)

        _registrar_operacion(
            current_user,
            'transfer',
            f'Transfer of {amount} to user {receiver.id}'
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Transfer could not be completed'}), 500

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

    to_user_id = request.form.get(
        'to_user_id', body.get('to_user_id')
    )

    amount_value = request.form.get(
        'amount', body.get('amount')
    )

    description = request.form.get(
        'description', body.get('description', 'QuickPay')
    )

    try:
        amount = _parse_amount(amount_value)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400

    receiver = User.query.get(to_user_id)

    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    if receiver.id == current_user.id:
        return jsonify({'error': 'Cannot pay yourself'}), 400

    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    try:
        current_user.balance -= amount
        receiver.balance += amount

        transaction = Transaction(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            amount=amount,
            description=sanitize_log_value(description, 200),
            status='completed',
            completed_at=datetime.utcnow()
        )

        db.session.add(transaction)

        _registrar_operacion(
            current_user,
            'quickpay',
            f'QuickPay of {amount} to user {receiver.id}'
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({'error': 'QuickPay could not be completed'}), 500

    return jsonify({
        'message': 'QuickPay sent',
        'transaction': transaction.to_dict()
    })










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
    data = request.get_json(silent=True) or {}

    to_user_id = data.get('to_user_id', current_user.id)

    try:
        amount = _parse_amount(data.get('amount'))
    except ValueError as error:
        return jsonify({'error': str(error)}), 400

    payee = User.query.get(to_user_id)

    if not payee:
        return jsonify({'error': 'User not found'}), 404

    if payee.id == current_user.id:
        return jsonify({'error': 'Cannot split a bill with yourself'}), 400

    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    try:
        current_user.balance -= amount
        payee.balance += amount

        transaction = Transaction(
            sender_id=current_user.id,
            receiver_id=payee.id,
            amount=amount,
            description=sanitize_log_value(
                data.get('description', 'Bill split'), 200
            ),
            status='completed',
            completed_at=datetime.utcnow()
        )

        db.session.add(transaction)

        _registrar_operacion(
            current_user,
            'split_bill',
            f'Bill split of {amount} to user {payee.id}'
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Bill split could not be completed'}), 500

    return jsonify({
        'message': 'Bill split',
        'transaction': transaction.to_dict()
    })
