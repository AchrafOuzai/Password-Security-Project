from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_123'  # Insecure key for demo purposes

# Database configuration
DATABASE = 'database.db'

def get_db_connection():
    """Create a connection to the database"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with the users table"""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Database successfully initialized!")

def hash_password_md5(password):
    """VULNERABLE function: MD5 hashing without salt"""
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # VULNERABLE MD5 hashing (no salt)
        hashed_password = hash_password_md5(password)
        
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                (username, hashed_password, email)
            )
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('This username already exists!', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password for comparison
        hashed_password = hash_password_md5(password)
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, hashed_password)
        ).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Retrieve all hashes for demo purposes (VULNERABILITY)
    all_users = conn.execute('SELECT username, password FROM users').fetchall()
    conn.close()
    
    return render_template('dashboard.html', user=user, all_users=all_users)

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/create_test_accounts')
def create_test_accounts():
    """Create test accounts with weak passwords"""
    test_accounts = [
        ('admin', 'password123', 'admin@example.com'),
        ('user1', '123456', 'user1@example.com'),
        ('alice', 'qwerty', 'alice@example.com'),
        ('bob', 'letmein', 'bob@example.com'),
        ('charlie', 'admin', 'charlie@example.com'),
        ('david', 'welcome', 'david@example.com'),
        ('eve', 'password', 'eve@example.com'),
        ('frank', '12345678', 'frank@example.com'),
    ]
    
    conn = get_db_connection()
    created = 0
    for username, password, email in test_accounts:
        try:
            hashed = hash_password_md5(password)
            conn.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                (username, hashed, email)
            )
            created += 1
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()
    
    flash(f'{created} test accounts created successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Initialize the database at startup
    init_db()
    print("\n" + "="*50)
    print("VULNERABLE APPLICATION - MD5 without Salt")
    print("="*50)
    print("\nThis application uses MD5 for password hashing.")
    print("WARNING: This is a DEMONSTRATION of a vulnerability!")
    print("\nTo create test accounts, visit: http://127.0.0.1:5000/create_test_accounts")
    print("="*50 + "\n")
    
    app.run(debug=True, port=5000)
