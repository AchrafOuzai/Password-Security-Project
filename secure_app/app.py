from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import secrets
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure randomly generated key

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
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Secure database initialized!")

def hash_password_bcrypt(password):
    """SECURE function: bcrypt hash with automatic salt"""
    # bcrypt automatically generates a unique salt
    # 12 rounds = balance between security and performance
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed_password):
    """Verify a password using bcrypt"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def validate_password_strength(password):
    """
    Validate password strength
    Rules:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    return len(errors) == 0, errors

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
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        
        # Password validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        
        is_valid, errors = validate_password_strength(password)
        if not is_valid:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')
        
        # SECURE hash with bcrypt (automatically generates salt)
        hashed_password = hash_password_bcrypt(password)
        
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
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        # Secure bcrypt verification
        if user and verify_password(password, user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Generic message to avoid revealing whether user exists
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
    
    # Retrieve statistics (without exposing hashes!)
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    conn.close()
    
    return render_template('dashboard.html', user=user, total_users=total_users)

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('Successfully logged out!', 'info')
    return redirect(url_for('index'))

@app.route('/security_info')
def security_info():
    """Security information page"""
    return render_template('security_info.html')

if __name__ == '__main__':
    # Initialize the database on startup
    init_db()
    print("\n" + "="*60)
    print("🔒 SECURE APPLICATION - bcrypt with Salt")
    print("="*60)
    print("\nThis application uses bcrypt for secure password hashing.")
    print("\nImplemented security measures:")
    print("  ✅ bcrypt with 12 rounds")
    print("  ✅ Automatically generated salt for each password")
    print("  ✅ Strong password policy (12+ characters)")
    print("  ✅ Server-side validation")
    print("  ✅ Hashes not exposed in the interface")
    print("  ✅ Generic error messages")
    print("="*60 + "\n")
    
    app.run(debug=True, port=5001)
