from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_dance.contrib.google import make_google_blueprint, google
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = '8sVKfL9OHC-dZPdJpblMBA'  # Secret key for session management

# Set up Google OAuth2 login
google_bp = make_google_blueprint(client_id='YOUR_GOOGLE_CLIENT_ID',
                                  client_secret='YOUR_GOOGLE_CLIENT_SECRET',
                                  redirect_to='google_login',
                                  scope=['profile', 'email'])  # Add necessary scopes (email, profile)
app.register_blueprint(google_bp, url_prefix='/google_login')

# MySQL Database Connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',    # Your MySQL host
        user='root',         # Your MySQL user
        password='Basu@2003', # Your MySQL password
        database='intrusion_system'  # Your database name
    )

# Send OTP to email function
def send_otp_to_email(recipient_email, otp):
    sender_email = 'your_email@example.com'  # Use your own email here
    sender_password = 'your_email_password'  # Use your email password here
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = 'Password Reset OTP'
    
    body = f'Your OTP for password reset is: {otp}'
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
    except Exception as e:
        print(f"Error sending OTP: {e}")

# Step 1: Render the home page
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))  # Redirect to dashboard if logged in
    return render_template('login.html')  # Show the login page if not logged in

# Step 2: Handle the login functionality
@app.route('/login', methods=['POST', 'GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))  # Redirect to dashboard if already logged in

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        # Check if user exists and password matches
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']  # Store user session
            return redirect(url_for('dashboard'))  # Redirect to dashboard after successful login
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials, please try again.'}), 401  # Unauthorized error

    return render_template('login.html')  # Show the login page on GET request

# Step 3: Handle the registration functionality
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Check if email already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            error_message = "Email already exists."
            return render_template('register.html', error_message=error_message)  # Show error if email exists

        # Hash the password before storing it using pbkdf2:sha256
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
        conn.commit()
        
        return redirect(url_for('home'))  # Redirect to login page after successful registration
    
    return render_template('register.html')  # Show the register page on GET request

# Google login route
@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    # Get the user's Google profile info using the updated API endpoint
    resp = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
    assert resp.ok, resp.text
    user_info = resp.json()

    # Store the user's info in the session
    session['google_user'] = user_info

    # Check if the user exists in the database, if not, create a new user
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (user_info['email'],))
    user = cursor.fetchone()

    if user:
        # User already exists, log them in
        session['user_id'] = user['id']
    else:
        # New user, register them
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (user_info['email'], 'default_password'))
        conn.commit()
        session['user_id'] = cursor.lastrowid  # Assign the new user id to session

    return redirect(url_for('dashboard'))  # Redirect to dashboard after successful login

# Step 4: Handle the dashboard route (user area after login)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Redirect to login if not logged in
    return render_template('dashboard.html')  # Show dashboard page if logged in

# Step 5: Handle the 'predict' page (a second feature page)
@app.route('/predict')
def predict():
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Redirect to login if not logged in
    return render_template('predict.html')  # Show prediction form if logged in

# Step 6: Handle the 'upload' page (a third feature page)
@app.route('/upload')
def upload():
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Redirect to login if not logged in
    return render_template('upload.html')  # Show upload page if logged in

# Step 7: Handle the logout functionality
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user session
    return redirect(url_for('home'))  # Redirect to home/login page after logging out

# Forgot Password - Send OTP route
@app.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        otp = random.randint(100000, 999999)

        # Send OTP to user's email
        send_otp_to_email(email, otp)

        # Store OTP in session for later verification
        session['otp'] = otp
        session['email'] = email

        return redirect(url_for('verify_otp'))  # Redirect to OTP verification page
    
    return render_template('forgot_password.html')  # Show forgot password page

# Verify OTP route
@app.route('/verify_otp', methods=['POST', 'GET'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        # Check if OTP matches
        if int(entered_otp) == session.get('otp'):
            return redirect(url_for('reset_password'))  # Redirect to password reset page
        else:
            error_message = "Invalid OTP, please try again."
            return render_template('forgot_password.html', error_message=error_message)
    
    return render_template('verify_otp.html')  # Show OTP verification page

# Reset Password route
@app.route('/reset_password', methods=['POST', 'GET'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']

        # Hash the new password
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

        # Update password in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, session.get('email')))
        conn.commit()

        return redirect(url_for('home'))  # Redirect to login page after password reset
    
    return render_template('reset_password.html')  # Show reset password page

if __name__ == '__main__':
    app.run(debug=True)
