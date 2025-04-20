from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import get_db_connection
from datetime import datetime

finance = Blueprint('finance', __name__)

@finance.route('/transactions', methods=['GET', 'POST'])
@login_required
def transactions():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            amount = float(request.form.get('amount', 0))
            description = request.form.get('description', '').strip()
            date = request.form.get('date')
            category_id = int(request.form.get('category_id', 0))
            
            if not all([amount, description, date, category_id]):
                flash('Please fill in all fields', 'danger')
                return redirect(url_for('finance.transactions'))
            
            cursor.execute('''
                INSERT INTO transactions (amount, description, date, user_id, category_id)
                VALUES (%s, %s, %s, %s, %s)
            ''', (amount, description, date, current_user.id, category_id))
            connection.commit()
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('finance.transactions'))
        
        # Get categories for dropdown
        cursor.execute('SELECT * FROM categories WHERE user_id = %s ORDER BY name', (current_user.id,))
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
        flash('An error occurred', 'danger')
        return redirect(url_for('index'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        connection.close()

@finance.route('/categories', methods=['GET', 'POST'])
@login_required
def categories():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            category_type = request.form.get('type')
            
            if not all([name, category_type]):
                flash('Please fill in all fields', 'danger')
                return redirect(url_for('finance.categories'))
            
            cursor.execute('''
                INSERT INTO categories (name, type, user_id)
                VALUES (%s, %s, %s)
            ''', (name, category_type, current_user.id))
            connection.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('finance.categories'))
        
        cursor.execute('''
            SELECT * FROM categories 
            WHERE user_id = %s 
            ORDER BY type, name
        ''', (current_user.id,))
        categories = cursor.fetchall()
        
        return render_template('categories.html', categories=categories)
        
    except Exception as e:
        flash('An error occurred', 'danger')
        return redirect(url_for('index'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        connection.close()

@finance.route('/dashboard')
@login_required
def dashboard():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
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
                            expense_categories=expense_categories)
        
    except Exception as e:
        flash('An error occurred', 'danger')
        return redirect(url_for('index'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        connection.close() 