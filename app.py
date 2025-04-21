from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import random
from flask import Response
import io
import csv
from gemini_helper import analyze_transactions_csv
import os, csv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'finance.db')

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database connection function
def get_db_connection():
    try:
        # Debug prints to check environment variables
        print(f"DB_HOST: {os.getenv('DB_HOST')}")
        print(f"DB_USER: {os.getenv('DB_USER')}")
        print(f"DB_PASSWORD: {os.getenv('DB_PASSWORD')}")
        print(f"DB_NAME: {os.getenv('DB_NAME')}")
        
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'finance_db')
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Initialize database
def init_db():
    try:
        connection = get_db_connection()
        if not connection:
            return None
            
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create categories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(50) NOT NULL,
                user_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Create transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                amount DECIMAL(10, 2) NOT NULL,
                description TEXT,
                date DATE NOT NULL,
                user_id INT NOT NULL,
                category_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE
            )
        ''')
        
        # Create budget_goals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS budget_goals (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                category_id INT NOT NULL,
                target_amount DECIMAL(10, 2) NOT NULL,
                period VARCHAR(20) NOT NULL, -- 'daily', 'weekly', 'monthly', 'yearly'
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE,
                UNIQUE KEY unique_user_category_period (user_id, category_id, period)
            )
        ''')
        
        connection.commit()
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

# Initialize database
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
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            
            if user_data:
                return User(user_data)
        except Exception as e:
            print(f"Error loading user: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
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
                cursor = connection.cursor(dictionary=True)
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user_data = cursor.fetchone()
                
                if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
                    user = User(user_data)
                    login_user(user)
                    flash('You have been logged in successfully!', 'success')
                    return redirect(url_for('transactions'))
                else:
                    flash('Invalid username or password', 'danger')
            except Exception as e:
                print(f"Error during login: {e}")
                flash('An error occurred during login. Please try again.', 'danger')
            finally:
                if 'cursor' in locals():
                    cursor.close()
                if connection:
                    connection.close()
        else:
            flash('Database connection error. Please try again later.', 'danger')
    
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
                cursor = connection.cursor(dictionary=True)
                
                # Check if username exists
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    flash('Username already exists', 'danger')
                    return render_template('register.html')
                
                # Check if email exists
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Email already exists', 'danger')
                    return render_template('register.html')
                
                # Create new user
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed_password, datetime.utcnow())
                )
                connection.commit()
                                # Get the user ID of the newly created user
                user_id = cursor.lastrowid
                
                # Add default categories for the new user
                default_income_categories = [
                    # Primary Income
                    'Salary',
                    'Business Income',
                    'Freelance',
                    'Rental Income',
                    'Investment Income',
                    'Interest Income',
                    'Dividend Income',
                    'Pension',
                    'Social Security',
                    'Other Income',
                    
                    # Additional Income Sources
                    'Commission',
                    'Tips',
                    'Gifts',
                    'Refunds',
                    'Lottery/Gambling',
                    'Insurance Claims',
                    'Tax Refunds'
                ]
                
                default_expense_categories = [
                    # Housing & Utilities
                    'Rent/Mortgage',
                    'Property Tax',
                    'Home Insurance',
                    'Maintenance',
                    'Furniture',
                    'Utilities',
                    'Internet',
                    'Phone',
                    'Cable TV',
                    
                    # Transportation
                    'Car Payment',
                    'Car Insurance',
                    'Gas',
                    'Public Transit',
                    'Parking',
                    'Car Maintenance',
                    'Tolls',
                    
                    # Food & Dining
                    'Groceries',
                    'Restaurants',
                    'Coffee Shops',
                    'Fast Food',
                    'Alcohol',
                    'Food Delivery',
                    
                    # Healthcare
                    'Health Insurance',
                    'Doctor Visits',
                    'Dentist',
                    'Pharmacy',
                    'Vision Care',
                    'Medical Supplies',
                    
                    # Personal Care
                    'Haircuts',
                    'Cosmetics',
                    'Spa/Massage',
                    'Gym Membership',
                    'Personal Care Products',
                    
                    # Education
                    'Tuition',
                    'Books',
                    'Student Loans',
                    'Courses',
                    'School Supplies',
                    
                    # Entertainment
                    'Movies',
                    'Concerts',
                    'Sports Events',
                    'Streaming Services',
                    'Games',
                    'Hobbies',
                    
                    # Shopping
                    'Clothing',
                    'Electronics',
                    'Home Goods',
                    'Gifts',
                    'Books',
                    
                    # Financial
                    'Credit Card Payments',
                    'Loan Payments',
                    'Investments',
                    'Savings',
                    'Charitable Donations',
                    
                    # Travel
                    'Airfare',
                    'Hotels',
                    'Vacation',
                    'Travel Insurance',
                    'Souvenirs',
                    
                    # Pets
                    'Pet Food',
                    'Veterinary',
                    'Pet Supplies',
                    'Pet Insurance',
                    
                    # Miscellaneous
                    'Subscriptions',
                    'Memberships',
                    'Postage',
                    'Bank Fees',
                    'Other Expenses'
                ]
                
                for category_name in default_income_categories:
                    cursor.execute(
                        "INSERT INTO categories (name, type, user_id, created_at) VALUES (%s, %s, %s, %s)",
                        (category_name, 'income', user_id, datetime.utcnow())
                    )
                
                for category_name in default_expense_categories:
                    cursor.execute(
                        "INSERT INTO categories (name, type, user_id, created_at) VALUES (%s, %s, %s, %s)",
                        (category_name, 'expense', user_id, datetime.utcnow())
                    )
                
                connection.commit()
                flash('Your account has been created! You can now log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Error during registration: {e}")
                flash('An error occurred during registration. Please try again.', 'danger')
            finally:
                if 'cursor' in locals():
                    cursor.close()
                if connection:
                    connection.close()
        else:
            flash('Database connection error. Please try again later.', 'danger')
    
    return render_template('register.html')

@app.route('/transactions', methods=['GET', 'POST'])
@login_required
def transactions():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            try:
                amount = float(request.form['amount'])
                description = request.form['description']
                date = request.form['date']
                category_id = int(request.form['category_id'])
                
                if amount <= 0:
                    flash('Amount must be greater than 0', 'danger')
                    return redirect(url_for('transactions'))
                
                if not description.strip():
                    flash('Description cannot be empty', 'danger')
                    return redirect(url_for('transactions'))
                
                # Verify category exists and belongs to user
                cursor.execute('''
                    SELECT id FROM categories 
                    WHERE id = %s AND user_id = %s
                ''', (category_id, current_user.id))
                if not cursor.fetchone():
                    flash('Invalid category selected', 'danger')
                    return redirect(url_for('transactions'))
                
                # Add the transaction
                cursor.execute('''
                    INSERT INTO transactions (amount, description, date, user_id, category_id)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (amount, description, date, current_user.id, category_id))
                
                # Check for budget alerts
                cursor.execute('''
                    SELECT bg.*, c.name as category_name
                    FROM budget_goals bg
                    JOIN categories c ON bg.category_id = c.id
                    WHERE bg.category_id = %s AND bg.user_id = %s
                ''', (category_id, current_user.id))
                budget_goal = cursor.fetchone()
                
                if budget_goal:
                    # Calculate total spending for the period
                    if budget_goal['period'] == 'daily':
                        date_filter = 'DATE(date) = DATE(%s)'
                    elif budget_goal['period'] == 'weekly':
                        date_filter = 'YEARWEEK(date) = YEARWEEK(%s)'
                    elif budget_goal['period'] == 'monthly':
                        date_filter = 'YEAR(date) = YEAR(%s) AND MONTH(date) = MONTH(%s)'
                    else:  # yearly
                        date_filter = 'YEAR(date) = YEAR(%s)'
                    
                    cursor.execute(f'''
                        SELECT COALESCE(SUM(amount), 0) as total_spent
                        FROM transactions
                        WHERE user_id = %s 
                        AND category_id = %s
                        AND {date_filter}
                    ''', (date, current_user.id, category_id))
                    result = cursor.fetchone()
                    total_spent = result['total_spent'] if result else 0
                    
                    # Check if budget is exceeded
                    if total_spent > budget_goal['target_amount']:
                        amount_exceeded = total_spent - budget_goal['target_amount']
                        flash(f'Budget Alert! You have exceeded your {budget_goal["period"]} budget for {budget_goal["category_name"]} by ₹{amount_exceeded:.2f}', 'warning')
                
                connection.commit()
                flash('Transaction added successfully!', 'success')
                return redirect(url_for('transactions'))
                
            except ValueError:
                flash('Invalid input format. Please check your entries.', 'danger')
                return redirect(url_for('transactions'))
            except Exception as e:
                print(f"Error adding transaction: {str(e)}")
                flash(f'Error adding transaction: {str(e)}', 'danger')
                return redirect(url_for('transactions'))
        
        # Get categories for the dropdown
        cursor.execute('SELECT * FROM categories WHERE user_id = %s', (current_user.id,))
        categories = cursor.fetchall()
        
        # Get transactions
        cursor.execute('''
            SELECT t.*, c.name as category_name, c.type as category_type
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = %s
            ORDER BY t.date DESC
        ''', (current_user.id,))
        transactions = cursor.fetchall()
        
        return render_template('transactions.html', transactions=transactions, categories=categories)
        
    except Exception as e:
        print(f"Error in transactions route: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('index'))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/notifications')
@login_required
def notifications():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get all notifications for the user
        cursor.execute("""
            SELECT * FROM notifications
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (current_user.id,))
        notifications_list = cursor.fetchall()
        
        # Mark all notifications as read
        cursor.execute("""
            UPDATE notifications
            SET is_read = TRUE
            WHERE user_id = %s AND is_read = FALSE
        """, (current_user.id,))
        connection.commit()
        
        return render_template('notifications.html', notifications=notifications_list)
    
    except Exception as e:
        print(f"Error in notifications page: {e}")
        flash('Error loading notifications', 'danger')
        return redirect(url_for('index'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/api/notifications/unread-count')
@login_required
def unread_notifications_count():
    connection = get_db_connection()
    if not connection:
        return jsonify({'count': 0})
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM notifications
            WHERE user_id = %s AND is_read = FALSE
        """, (current_user.id,))
        result = cursor.fetchone()
        return jsonify({'count': result['count']})
    
    except Exception as e:
        print(f"Error getting unread notifications count: {e}")
        return jsonify({'count': 0})
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/api/transactions/<int:transaction_id>', methods=['GET', 'DELETE'])
@login_required
def transaction_api(transaction_id):
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'GET':
            # Get transaction details
            cursor.execute("""
                SELECT t.*, c.name as category_name, c.type as category_type
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.id = %s AND t.user_id = %s
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
            cursor.execute("DELETE FROM transactions WHERE id = %s AND user_id = %s", 
                         (transaction_id, current_user.id))
            connection.commit()
            return jsonify({'message': 'Transaction deleted successfully'})
    
    except Exception as e:
        print(f"Error in transaction API: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/categories', methods=['GET', 'POST'])
@login_required
def categories():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            # Handle category creation
            name = request.form.get('name')
            category_type = request.form.get('type')
            
            cursor.execute(
                "INSERT INTO categories (name, type, user_id, created_at) VALUES (%s, %s, %s, %s)",
                (name, category_type, current_user.id, datetime.utcnow())
            )
            connection.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('categories'))
        
        # Get all categories
        cursor.execute("SELECT * FROM categories WHERE user_id = %s ORDER BY type, name", (current_user.id,))
        categories_list = cursor.fetchall()
        
        return render_template('categories.html', categories=categories_list)
    except Exception as e:
        print(f"Error in categories page: {e}")
        flash('Error loading categories', 'danger')
        return redirect(url_for('transactions'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            # Handle profile update
            username = request.form.get('username')
            email = request.form.get('email')
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            
            # Verify current password
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
            user_data = cursor.fetchone()
            
            if not bcrypt.check_password_hash(user_data['password_hash'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            # Update user information
            update_fields = []
            update_values = []
            
            if username and username != current_user.username:
                # Check if username is already taken
                cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (username, current_user.id))
                if cursor.fetchone():
                    flash('Username is already taken', 'danger')
                    return redirect(url_for('profile'))
                update_fields.append("username = %s")
                update_values.append(username)
            
            if email and email != current_user.email:
                # Check if email is already taken
                cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, current_user.id))
                if cursor.fetchone():
                    flash('Email is already taken', 'danger')
                    return redirect(url_for('profile'))
                update_fields.append("email = %s")
                update_values.append(email)
            
            if new_password:
                update_fields.append("password_hash = %s")
                update_values.append(bcrypt.generate_password_hash(new_password).decode('utf-8'))
            
            if update_fields:
                update_values.append(current_user.id)
                query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
                cursor.execute(query, tuple(update_values))
                connection.commit()
                
                # Update current user object
                if username:
                    current_user.username = username
                if email:
                    current_user.email = email
                
                flash('Profile updated successfully', 'success')
                return redirect(url_for('profile'))
        
        # Get user data for display
        cursor.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
        user_data = cursor.fetchone()
        
        return render_template('profile.html', user=user_data)
    
    except Exception as e:
        print(f"Error in profile page: {e}")
        flash('Error updating profile', 'danger')
        return redirect(url_for('profile'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

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
        cursor = connection.cursor(dictionary=True)
        cursor.execute("DELETE FROM transactions WHERE id = %s AND user_id = %s", (transaction_id, current_user.id))
        connection.commit()
        return jsonify({'message': 'Transaction deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting transaction: {e}")
        return jsonify({'error': 'Error deleting transaction'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("DELETE FROM categories WHERE id = %s AND user_id = %s", (category_id, current_user.id))
        connection.commit()
        return jsonify({'message': 'Category deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting category: {e}")
        return jsonify({'error': 'Error deleting category'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/dashboard')
@login_required
def dashboard():
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get total income and expenses
            cursor.execute('''
                SELECT 
                    SUM(CASE WHEN c.type = 'income' THEN t.amount ELSE 0 END) as total_income,
                    SUM(CASE WHEN c.type = 'expense' THEN t.amount ELSE 0 END) as total_expenses
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.user_id = %s
            ''', (current_user.id,))
            totals = cursor.fetchone()
            
            # Get monthly data for charts
            cursor.execute('''
                SELECT 
                    DATE_FORMAT(t.date, '%%Y-%%m') as month,
                    SUM(CASE WHEN c.type = 'income' THEN t.amount ELSE 0 END) as income,
                    SUM(CASE WHEN c.type = 'expense' THEN t.amount ELSE 0 END) as expenses
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.user_id = %s
                GROUP BY DATE_FORMAT(t.date, '%%Y-%%m')
                ORDER BY month DESC
                LIMIT 12
            ''', (current_user.id,))
            monthly_data = cursor.fetchall()
            
            # Calculate monthly savings
            if monthly_data:
                latest_month = monthly_data[0]
                monthly_savings = (latest_month.get('income', 0) or 0) - (latest_month.get('expenses', 0) or 0)
            else:
                monthly_savings = 0
            
            # Get recent transactions
            cursor.execute('''
                SELECT t.*, c.name as category_name, c.type as category_type
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.user_id = %s
                ORDER BY t.date DESC
                LIMIT 5
            ''', (current_user.id,))
            recent_transactions = cursor.fetchall()
        
            # Get category breakdown
            cursor.execute('''
                SELECT 
                    c.name,
                    c.type,
                    SUM(t.amount) as total,
                    COUNT(*) as count,
                    (SUM(t.amount) / (
                        SELECT SUM(amount) 
                        FROM transactions t2 
                        JOIN categories c2 ON t2.category_id = c2.id 
                        WHERE t2.user_id = %s AND c2.type = c.type
                    )) * 100 as percentage
                FROM transactions t
                JOIN categories c ON t.category_id = c.id
                WHERE t.user_id = %s
                GROUP BY c.id, c.name, c.type
                HAVING total > 0
                ORDER BY total DESC
            ''', (current_user.id, current_user.id))
            categories = cursor.fetchall()
            
            # Separate income and expense categories
            income_categories = [c for c in categories if c['type'] == 'income']
            expense_categories = [c for c in categories if c['type'] == 'expense']
            
            return render_template('dashboard.html',
                                totals=totals,
                                monthly_data=monthly_data,
                                recent_transactions=recent_transactions,
                                income_categories=income_categories,
                                expense_categories=expense_categories,
                                monthly_savings=monthly_savings)
            
        except Exception as e:
            print(f"Error in dashboard route: {e}")
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('index'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
    else:
        flash('Database connection error. Please try again later.', 'error')
        return redirect(url_for('index'))

@app.route('/budget', methods=['GET', 'POST'])
@login_required
def budget():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            category_id = request.form.get('category_id')
            target_amount = request.form.get('target_amount')
            period = request.form.get('period')
            
            if not category_id or not target_amount or not period:
                flash('Please fill in all fields', 'error')
                return redirect(url_for('budget'))
            
            try:
                target_amount = float(target_amount)
                if target_amount <= 0:
                    flash('Target amount must be greater than 0', 'error')
                    return redirect(url_for('budget'))
            except ValueError:
                flash('Invalid target amount', 'error')
                return redirect(url_for('budget'))
            
            # Insert or update the budget goal
            cursor.execute('''
                INSERT INTO budget_goals (user_id, category_id, target_amount, period)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE target_amount = %s, period = %s
            ''', (current_user.id, category_id, target_amount, period, target_amount, period))
            
            connection.commit()
            flash('Budget goal set successfully!', 'success')
            return redirect(url_for('budget'))
        
        # Get all categories with their goals and spending
        cursor.execute('''
            SELECT c.id, c.name, 
                   COALESCE(g.target_amount, 0) as target_amount,
                   COALESCE(g.period, 'monthly') as period,
                   COALESCE(SUM(t.amount), 0) as spent,
                   MIN(t.date) as first_transaction,
                   MAX(t.date) as last_transaction
            FROM categories c
            LEFT JOIN budget_goals g ON c.id = g.category_id AND g.user_id = %s
            LEFT JOIN transactions t ON c.id = t.category_id AND t.user_id = %s
            WHERE c.user_id = %s
            GROUP BY c.id, c.name, g.target_amount, g.period
            ORDER BY c.name
        ''', (current_user.id, current_user.id, current_user.id))
        
        categories = cursor.fetchall()
        
        # Calculate remaining budget and percentage for each category
        for category in categories:
            category['remaining'] = category['target_amount'] - category['spent']
            if category['target_amount'] > 0:
                # Calculate actual percentage for notifications
                actual_percentage = (category['spent'] / category['target_amount']) * 100
                # Cap the percentage at 100% for the progress bar
                category['percentage'] = min(100, actual_percentage)
                
                # Calculate date range based on period
                today = datetime.now().date()
                if category['period'] == 'weekly':
                    # Get the start of the current week (Monday)
                    start_of_week = today - timedelta(days=today.weekday())
                    end_of_week = start_of_week + timedelta(days=6)
                    category['date_range'] = f"{start_of_week.strftime('%d %b')} - {end_of_week.strftime('%d %b %Y')}"
                elif category['period'] == 'monthly':
                    start_of_month = today.replace(day=1)
                    end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
                    category['date_range'] = f"{start_of_month.strftime('%d %b')} - {end_of_month.strftime('%d %b %Y')}"
                elif category['period'] == 'yearly':
                    start_of_year = today.replace(month=1, day=1)
                    end_of_year = today.replace(month=12, day=31)
                    category['date_range'] = f"{start_of_year.strftime('%d %b %Y')} - {end_of_year.strftime('%d %b %Y')}"
                else:  # daily
                    category['date_range'] = today.strftime('%d %b %Y')
                
                # Add fun notifications based on budget usage
                if actual_percentage >= 90:
                    messages_90 = [
                        '90% ho gaya! Budget bol raha hai—"It\'s not you, it\'s me... being totally khali!"',
                        '90%?! Party ruko, warna EMI bhi naraaz ho jayegi!',
                        '90%?! Budget ki haalat dekh ke toh UPI bhi sharma jayega!',
                        '90%?! Ab toh budget bhi bol raha hai "Main jaa raha hoon, tum sambhal lo!"'
                    ]
                    exceeded = category['spent'] - category['target_amount']
                    flash(f'Budget Alert! {random.choice(messages_90)} You\'ve exceeded your {category["period"]} budget ({category["date_range"]}) by ₹{exceeded:.2f}!', 'warning')
                elif actual_percentage >= 80:
                    messages_80 = [
                        '80%?! Paisa uda jaise dil uda swipe karte waqt!',
                        '80%?! Budget dekh ke toh credit card bhi piche hat gaya!',
                        '80%?! Thoda brake maar yaar, warna savings ka breakup ho jayega!',
                        '80%?! Budget ki haalat dekh ke toh piggy bank bhi ro padegi!'
                    ]
                    exceeded = category['spent'] - category['target_amount']
                    flash(f'Budget Alert! {random.choice(messages_80)} You\'ve exceeded your {category["period"]} budget ({category["date_range"]}) by ₹{exceeded:.2f}!', 'warning')
                elif actual_percentage >= 50:
                    messages_50 = [
                        'Arey waah, aadha budget uda diya! Date pe jaise kharcha—controlled but thoda naughty.',
                        '50% ho gaya! Budget dekh raha hai tumhe—thoda sambhal ja!',
                        'Aadha budget gaya... jaise dil gaya jab tumne bina soche kharcha kiya!',
                        '50%?! Thoda slow karo yaar, warna savings ka mood kharab ho jayega!'
                    ]
                    flash(f'Budget Alert! {random.choice(messages_50)} You\'ve spent ₹{category["spent"]:.2f} out of ₹{category["target_amount"]:.2f} for {category["period"]} ({category["date_range"]})', 'info')
            else:
                category['percentage'] = 0
                category['date_range'] = ''
        
        return render_template('budget.html', categories=categories)
        
    except Exception as e:
        print(f"Error in budget route: {str(e)}")
        flash('An error occurred while processing your request', 'error')
        return redirect(url_for('budget'))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/api/budget/<int:category_id>', methods=['DELETE'])
@login_required
def delete_budget(category_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Delete the budget goal
        cursor.execute('''
            DELETE FROM budget_goals 
            WHERE user_id = %s AND category_id = %s
        ''', (current_user.id, category_id))
        
        connection.commit()
        return '', 204
        
    except Exception as e:
        print(f"Error deleting budget: {str(e)}")
        return jsonify({'error': 'Failed to delete budget goal'}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route('/export-csv', methods=['GET'])
@login_required
def export_csv():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('transactions'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute('''
            SELECT t.amount, t.description, t.date, c.name as category_name, c.type as category_type
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = %s
            ORDER BY t.date DESC
        ''', (current_user.id,))
        transactions = cursor.fetchall()

        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Amount', 'Description', 'Category', 'Type'])  # Header

        for txn in transactions:
            writer.writerow([
                txn['date'].strftime('%Y-%m-%d') if txn['date'] else '',
                txn['amount'],
                txn['description'],
                txn['category_name'],
                txn['category_type']
            ])

        output.seek(0)

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=transactions.csv'}
        )
    except Exception as e:
        print(f"Error exporting CSV: {str(e)}")
        flash('Error exporting CSV file.', 'danger')
        return redirect(url_for('transactions'))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route('/suggestions')
@login_required
def suggestions():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('transactions'))

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute('''
            SELECT t.amount, t.description, t.date, c.name as category
            FROM transactions t
            JOIN categories c ON t.category_id = c.id
            WHERE t.user_id = %s
            ORDER BY t.date DESC
        ''', (current_user.id,))
        transactions = cursor.fetchall()

        # Save CSV
        
        filename = f"transactions_{current_user.id}.csv"
        filepath = os.path.join("temp", filename)
        os.makedirs("temp", exist_ok=True)

        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Amount', 'Description', 'Date', 'Category'])
            for tx in transactions:
                writer.writerow([tx['amount'], tx['description'], tx['date'], tx['category']])

        # Analyze with Gemini
        
        suggestions = analyze_transactions_csv(filepath)

        os.remove(filepath)  # Clean up

        return render_template('suggestions.html', suggestions=suggestions)

    except Exception as e:
        print("Error analyzing transactions:", str(e))
        flash("Failed to analyze transactions.", "danger")
        return redirect(url_for('transactions'))
    finally:
        cursor.close()
        connection.close()


if __name__ == '__main__':
    app.run(debug=True) 