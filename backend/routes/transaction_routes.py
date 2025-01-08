from flask import Blueprint, request, jsonify
from models import db, User, Transaction
from datetime import datetime
from decimal import Decimal
from auth import token_required

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
    
    # Add a basic security check
    if int(user_id) != current_user.id:
        return jsonify({'error': 'Unauthorized to view other users transactions'}), 403
    
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | 
        (Transaction.receiver_id == user_id)
    ).order_by(Transaction.created_at.desc()).all()
    
    return jsonify([{
        'id': t.id,
        'sender_id': t.sender_id,
        'receiver_id': t.receiver_id,
        'amount': float(t.amount),
        'description': t.description,
        'status': t.status,
        'created_at': t.created_at.isoformat(),
        'completed_at': t.completed_at.isoformat() if t.completed_at else None
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