from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error

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
        
        if connection:
            try:
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
                
                connection.commit()
                print("Database initialized successfully")
            except Exception as e:
                print(f"Error initializing database: {e}")
            finally:
                if 'cursor' in locals():
                    cursor.close()
                if connection:
                    connection.close()
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

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
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            if request.method == 'POST':
                amount = float(request.form['amount'])
                description = request.form['description']
                date = request.form['date']
                category_id = int(request.form['category_id'])
                
                cursor.execute('''
                    INSERT INTO transactions (amount, description, date, user_id, category_id)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (amount, description, date, current_user.id, category_id))
                
                connection.commit()
                flash('Transaction added successfully!', 'success')
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
            print(f"Error in transactions route: {e}")
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('dashboard'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if connection:
                connection.close()
    else:
        flash('Database connection error. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

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

if __name__ == '__main__':
    app.run(debug=True) 