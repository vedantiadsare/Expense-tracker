from datetime import datetime
from app import users_db, categories_db, transactions_db, Query
import uuid

def generate_id():
    return str(uuid.uuid4())

class User:
    @staticmethod
    def create(username, email, password_hash):
        user_id = generate_id()
        user_data = {
            'id': user_id,
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.utcnow().isoformat()
        }
        users_db.insert(user_data)
        return user_data

    @staticmethod
    def get_by_id(user_id):
        return users_db.get(Query().id == user_id)

    @staticmethod
    def get_by_username(username):
        return users_db.get(Query().username == username)

    @staticmethod
    def get_by_email(email):
        return users_db.get(Query().email == email)

class Category:
    @staticmethod
    def create(name, type, user_id):
        category_id = generate_id()
        category_data = {
            'id': category_id,
            'name': name,
            'type': type,
            'user_id': user_id
        }
        categories_db.insert(category_data)
        return category_data

    @staticmethod
    def get_by_user(user_id):
        return categories_db.search(Query().user_id == user_id)

    @staticmethod
    def get_by_id(category_id):
        return categories_db.get(Query().id == category_id)

class Transaction:
    @staticmethod
    def create(amount, type, category_id, user_id, description='', date=None):
        transaction_id = generate_id()
        transaction_data = {
            'id': transaction_id,
            'amount': amount,
            'description': description,
            'date': date.isoformat() if date else datetime.utcnow().isoformat(),
            'type': type,
            'user_id': user_id,
            'category_id': category_id,
            'created_at': datetime.utcnow().isoformat()
        }
        transactions_db.insert(transaction_data)
        return transaction_data

    @staticmethod
    def get_by_user(user_id):
        return transactions_db.search(Query().user_id == user_id)

    @staticmethod
    def get_by_id(transaction_id):
        return transactions_db.get(Query().id == transaction_id)

    @staticmethod
    def delete(transaction_id):
        transactions_db.remove(Query().id == transaction_id)

    @staticmethod
    def get_summary(user_id, start_date=None, end_date=None):
        query = Query().user_id == user_id
        if start_date:
            query = query & (Query().date >= start_date.isoformat())
        if end_date:
            query = query & (Query().date <= end_date.isoformat())
        
        transactions = transactions_db.search(query)
        
        total_income = sum(t['amount'] for t in transactions if t['type'] == 'income')
        total_expense = sum(t['amount'] for t in transactions if t['type'] == 'expense')
        balance = total_income - total_expense
        
        return {
            'total_income': total_income,
            'total_expense': total_expense,
            'balance': balance
        } 