from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Transaction, Category
from datetime import datetime

finance_bp = Blueprint('finance', __name__)

# Category routes
@finance_bp.route('/categories', methods=['GET'])
@login_required
def get_categories():
    categories = Category.get_by_user(current_user.id)
    return jsonify(categories), 200

@finance_bp.route('/categories', methods=['POST'])
@login_required
def create_category():
    data = request.get_json()
    
    if not all(k in data for k in ['name', 'type']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['type'] not in ['income', 'expense']:
        return jsonify({'error': 'Invalid category type'}), 400
    
    category_data = Category.create(
        name=data['name'],
        type=data['type'],
        user_id=current_user.id
    )
    
    return jsonify(category_data), 201

# Transaction routes
@finance_bp.route('/transactions', methods=['GET'])
@login_required
def get_transactions():
    transactions = Transaction.get_by_user(current_user.id)
    return jsonify(transactions), 200

@finance_bp.route('/transactions', methods=['POST'])
@login_required
def create_transaction():
    data = request.get_json()
    
    if not all(k in data for k in ['amount', 'type', 'category_id']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['type'] not in ['income', 'expense']:
        return jsonify({'error': 'Invalid transaction type'}), 400
    
    # Verify category belongs to user
    category = Category.get_by_id(data['category_id'])
    if not category or category['user_id'] != current_user.id:
        return jsonify({'error': 'Category not found'}), 404
    
    transaction_data = Transaction.create(
        amount=data['amount'],
        description=data.get('description', ''),
        type=data['type'],
        category_id=data['category_id'],
        user_id=current_user.id,
        date=datetime.fromisoformat(data['date']) if 'date' in data else None
    )
    
    return jsonify(transaction_data), 201

@finance_bp.route('/transactions/<transaction_id>', methods=['DELETE'])
@login_required
def delete_transaction(transaction_id):
    transaction = Transaction.get_by_id(transaction_id)
    
    if not transaction or transaction['user_id'] != current_user.id:
        return jsonify({'error': 'Transaction not found'}), 404
    
    Transaction.delete(transaction_id)
    return jsonify({'message': 'Transaction deleted successfully'}), 200

@finance_bp.route('/summary', methods=['GET'])
@login_required
def get_summary():
    # Get date range from query parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    start_date = datetime.fromisoformat(start_date) if start_date else None
    end_date = datetime.fromisoformat(end_date) if end_date else None
    
    summary = Transaction.get_summary(current_user.id, start_date, end_date)
    return jsonify(summary), 200 