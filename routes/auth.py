from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import create_access_token
from app import bcrypt, get_db_connection
from datetime import datetime
from models import User

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        connection = get_db_connection()
        if not connection:
            flash('Database connection error', 'danger')
            return render_template('login.html')
            
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            
            if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
                user = User(user_data)
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
        except Exception as e:
            flash('An error occurred during login', 'danger')
        finally:
            if 'cursor' in locals():
                cursor.close()
            connection.close()
    
    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        connection = get_db_connection()
        if not connection:
            flash('Database connection error', 'danger')
            return render_template('register.html')
            
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Check if username exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username already exists', 'danger')
                return render_template('register.html')
            
            # Check if email exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
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
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            flash('An error occurred during registration', 'danger')
        finally:
            if 'cursor' in locals():
                cursor.close()
            connection.close()
    
    return render_template('register.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@auth.route('/profile')
@login_required
def profile():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email
    }), 200 