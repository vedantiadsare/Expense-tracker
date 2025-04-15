from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import sqlite3
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'finance.db')

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database connection function
def get_db_connection():
    try:
        connection = sqlite3.connect(app.config['DATABASE'])
        connection.row_factory = sqlite3.Row
        return connection
    except Exception as e:
        print(f"Error connecting to SQLite: {e}")
        return None

# Initialize database
def init_db():
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create categories table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Create transactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    amount REAL NOT NULL,
                    description TEXT,
                    date TIMESTAMP NOT NULL,
                    user_id INTEGER NOT NULL,
                    category_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE
                )
            ''')
            
            connection.commit()
            print("Database initialized successfully")
        except Exception as e:
            print(f"Error initializing database: {e}")
        finally:
            connection.close()

# Initialize database on startup
init_db()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.created_at = user_data.get('created_at', datetime.utcnow())

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user_data = cursor.fetchone()
            
            if user_data:
                return User(dict(user_data))
        except Exception as e:
            print(f"Error loading user: {e}")
    return None

# Root route
@app.route('/')
def index():
    return render_template('index.html')

# Page routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('transactions'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user_data = cursor.fetchone()
                
                if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
                    user = User(dict(user_data))
                    login_user(user)
                    flash('You have been logged in successfully!', 'success')
                    return redirect(url_for('transactions'))
            except Exception as e:
                print(f"Error during login: {e}")
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('transactions'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()
                
                # Check if username exists
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    flash('Username already exists', 'danger')
                    return render_template('register.html')
                
                # Check if email exists
                cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
                if cursor.fetchone():
                    flash('Email already exists', 'danger')
                    return render_template('register.html')
                
                # Create new user
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, hashed_password, datetime.utcnow())
                )
                connection.commit()
                
                # Get the user ID of the newly created user
                user_id = cursor.lastrowid
                
                # Add default categories for the new user
                default_income_categories = ['Salary', 'Freelance', 'Investments', 'Gifts']
                default_expense_categories = ['Food', 'Transportation', 'Housing', 'Utilities', 'Entertainment', 'Shopping', 'Healthcare']
                
                for category_name in default_income_categories:
                    cursor.execute(
                        "INSERT INTO categories (name, type, user_id, created_at) VALUES (?, ?, ?, ?)",
                        (category_name, 'income', user_id, datetime.utcnow())
                    )
                
                for category_name in default_expense_categories:
                    cursor.execute(
                        "INSERT INTO categories (name, type, user_id, created_at) VALUES (?, ?, ?, ?)",
                        (category_name, 'expense', user_id, datetime.utcnow())
                    )
                
                connection.commit()
                
                flash('Your account has been created! You can now log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Error during registration: {e}")
                flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/transactions', methods=['GET', 'POST'])
@login_required
def transactions():
    print("Transactions route accessed")
    connection = get_db_connection()
    if not connection:
        print("Database connection failed")
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor()
        
        if request.method == 'POST':
            try:
                # Handle transaction creation/update
                transaction_id = request.form.get('transaction_id')
                amount = float(request.form.get('amount'))
                description = request.form.get('description')
                date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
                category_id = int(request.form.get('category_id'))
                
                # Get the category type
                cursor.execute("SELECT type FROM categories WHERE id = ? AND user_id = ?", 
                             (category_id, current_user.id))
                category = cursor.fetchone()
                if not category:
                    flash('Invalid category selected', 'danger')
                    return redirect(url_for('transactions'))
                
                if transaction_id:  # Update existing transaction
                    cursor.execute("""
                        UPDATE transactions 
                        SET amount = ?, description = ?, date = ?, category_id = ?
                        WHERE id = ? AND user_id = ?
                    """, (amount, description, date, category_id, transaction_id, current_user.id))
                    flash('Transaction updated successfully!', 'success')
                else:  # Create new transaction
                    cursor.execute("""
                        INSERT INTO transactions (amount, description, date, user_id, category_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (amount, description, date, current_user.id, category_id, datetime.utcnow()))
                    flash('Transaction added successfully!', 'success')
                
                connection.commit()
                return redirect(url_for('transactions'))
            except Exception as e:
                print(f"Error saving transaction: {e}")
                flash('Error saving transaction. Please try again.', 'danger')
        
        # Get all transactions
        try:
            print("Fetching transactions")
            cursor.execute("""
                SELECT t.*, c.name as category_name, c.type as category_type
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.user_id = ?
                ORDER BY t.date DESC
            """, (current_user.id,))
            transactions_list = cursor.fetchall()
            
            # Convert dates to proper format
            for transaction in transactions_list:
                if isinstance(transaction['date'], str):
                    try:
                        # Try to parse the date string to a datetime object
                        transaction['date'] = datetime.strptime(transaction['date'], '%Y-%m-%d')
                    except ValueError:
                        # If parsing fails, keep it as a string
                        pass
            
            print(f"Found {len(transactions_list)} transactions")
        except Exception as e:
            print(f"Error fetching transactions: {e}")
            transactions_list = []
        
        # Get categories for dropdown
        try:
            print("Fetching categories")
            cursor.execute("SELECT * FROM categories WHERE user_id = ? ORDER BY type, name", (current_user.id,))
            categories = cursor.fetchall()
            print(f"Found {len(categories)} categories")
        except Exception as e:
            print(f"Error fetching categories: {e}")
            categories = []
        
        cursor.close()
        connection.close()
        
        print("Rendering transactions template")
        return render_template('transactions.html', transactions=transactions_list, categories=categories)
    except Exception as e:
        print(f"Error in transactions page: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading transactions', 'danger')
        return redirect(url_for('index'))

@app.route('/api/transactions/<int:transaction_id>', methods=['GET', 'DELETE'])
@login_required
def transaction_api(transaction_id):
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        
        if request.method == 'GET':
            # Get transaction details
            cursor.execute("""
                SELECT t.*, c.name as category_name, c.type as category_type
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.id = ? AND t.user_id = ?
            """, (transaction_id, current_user.id))
            transaction = cursor.fetchone()
            
            if transaction:
                # Format the date properly
                date_str = transaction['date']
                if not isinstance(date_str, str):
                    date_str = date_str.strftime('%Y-%m-%d')
                
                return jsonify({
                    'id': transaction['id'],
                    'amount': transaction['amount'],
                    'description': transaction['description'],
                    'date': date_str,
                    'category_id': transaction['category_id'],
                    'category_name': transaction['category_name'],
                    'category_type': transaction['category_type']
                })
            else:
                return jsonify({'error': 'Transaction not found'}), 404
        
        elif request.method == 'DELETE':
            # Delete transaction
            cursor.execute("DELETE FROM transactions WHERE id = ? AND user_id = ?", 
                         (transaction_id, current_user.id))
            connection.commit()
            return jsonify({'message': 'Transaction deleted successfully'})
    
    except Exception as e:
        print(f"Error in transaction API: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/categories', methods=['GET', 'POST'])
@login_required
def categories():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor()
        
        if request.method == 'POST':
            # Handle category creation
            name = request.form.get('name')
            category_type = request.form.get('type')
            
            cursor.execute(
                "INSERT INTO categories (name, type, user_id, created_at) VALUES (?, ?, ?, ?)",
                (name, category_type, current_user.id, datetime.utcnow())
            )
            connection.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('categories'))
        
        # Get all categories
        cursor.execute("SELECT * FROM categories WHERE user_id = ? ORDER BY type, name", (current_user.id,))
        categories_list = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        return render_template('categories.html', categories=categories_list)
    except Exception as e:
        print(f"Error in categories page: {e}")
        flash('Error loading categories', 'danger')
        return redirect(url_for('transactions'))

@app.route('/profile')
@login_required
def profile():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (current_user.id,))
        user_data = cursor.fetchone()
        cursor.close()
        connection.close()
        
        return render_template('profile.html', user=dict(user_data))
    except Exception as e:
        print(f"Error loading profile: {e}")
        flash('Error loading profile', 'danger')
        return redirect(url_for('transactions'))

@app.route('/logout')
@login_required
def logout_page():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# API routes for transaction and category management
@app.route('/api/transactions/<int:transaction_id>', methods=['DELETE'])
@login_required
def delete_transaction(transaction_id):
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM transactions WHERE id = ? AND user_id = ?", (transaction_id, current_user.id))
        connection.commit()
        cursor.close()
        connection.close()
        
        return jsonify({'message': 'Transaction deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting transaction: {e}")
        return jsonify({'error': 'Error deleting transaction'}), 500

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM categories WHERE id = ? AND user_id = ?", (category_id, current_user.id))
        connection.commit()
        cursor.close()
        connection.close()
        
        return jsonify({'message': 'Category deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting category: {e}")
        return jsonify({'error': 'Error deleting category'}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total income and expenses
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN c.type = 'income' THEN t.amount ELSE 0 END) as total_income,
                SUM(CASE WHEN c.type = 'expense' THEN t.amount ELSE 0 END) as total_expenses
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = ?
        """, (current_user.id,))
        totals = dict(cursor.fetchone())
        
        # Get monthly data for chart
        cursor.execute("""
            SELECT 
                strftime('%Y-%m', t.date) as month,
                SUM(CASE WHEN c.type = 'income' THEN t.amount ELSE 0 END) as income,
                SUM(CASE WHEN c.type = 'expense' THEN t.amount ELSE 0 END) as expenses
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = ?
            GROUP BY strftime('%Y-%m', t.date)
            ORDER BY month DESC
            LIMIT 12
        """, (current_user.id,))
        monthly_data = [dict(row) for row in cursor.fetchall()]
        
        # Get recent transactions
        cursor.execute("""
            SELECT t.*, c.name as category_name, c.type as type
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = ?
            ORDER BY t.date DESC
            LIMIT 5
        """, (current_user.id,))
        recent_transactions = [dict(row) for row in cursor.fetchall()]
        
        # Get category breakdown
        cursor.execute("""
            SELECT 
                c.name,
                c.type,
                SUM(t.amount) as total,
                COUNT(*) as count
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = ?
            GROUP BY c.id, c.name, c.type
            ORDER BY total DESC
        """, (current_user.id,))
        categories = [dict(row) for row in cursor.fetchall()]
        
        # Calculate category percentages
        total_income = totals['total_income'] or 0
        total_expenses = totals['total_expenses'] or 0
        
        income_categories = []
        expense_categories = []
        
        for category in categories:
            if category['type'] == 'income':
                percentage = (category['total'] / total_income * 100) if total_income > 0 else 0
                income_categories.append({
                    'name': category['name'],
                    'total': category['total'],
                    'count': category['count'],
                    'percentage': round(percentage, 1)
                })
            else:
                percentage = (category['total'] / total_expenses * 100) if total_expenses > 0 else 0
                expense_categories.append({
                    'name': category['name'],
                    'total': category['total'],
                    'count': category['count'],
                    'percentage': round(percentage, 1)
                })
        
        return render_template('dashboard.html',
                             totals=totals,
                             monthly_data=monthly_data,
                             recent_transactions=recent_transactions,
                             income_categories=income_categories,
                             expense_categories=expense_categories)
                             
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return redirect(url_for('index'))
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    app.run(debug=True) 