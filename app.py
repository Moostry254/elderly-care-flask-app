import os
import secrets
from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# Import Click for creating CLI commands (usually installed with Flask)
import click
import traceback # Import traceback for better error logging

# --- App and Database Configuration ---

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder='templates')

# --- Database Configuration ---
database_url = os.environ.get('DATABASE_URL')
final_db_uri = None

if database_url:
    print("DATABASE_URL environment variable found.")
    if database_url.startswith("postgres://"):
        final_db_uri = database_url.replace("postgres://", "postgresql://", 1)
        print(f"Using Render PostgreSQL URI: {final_db_uri}")
    else:
        final_db_uri = database_url
        print(f"Using DATABASE_URL directly: {final_db_uri}")
else:
    print("DATABASE_URL environment variable NOT found. Falling back to local SQLite.")
    sqlite_path = os.path.join(basedir, 'local_dev.db')
    final_db_uri = 'sqlite:///' + sqlite_path
    print(f"Using local SQLite URI: {final_db_uri}")


app.config['SQLALCHEMY_DATABASE_URI'] = final_db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Secret Key Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
if not os.environ.get('SECRET_KEY'):
    print("Warning: SECRET_KEY environment variable not set. Using temporary key.")

db = SQLAlchemy(app)

# --- REMOVED TEMPORARY CODE TO CREATE TABLES ON DEPLOY ---
# The block that called db.create_all() on startup has been removed.
# Use the 'flask init-db' command or Render Shell for table creation/updates.


# --- Database Model Definition ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# --- Database Initialization Command ---
# This command allows you to create tables manually via `flask init-db`
@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    with app.app_context(): # Ensure commands run within application context
        print("Initializing the database...")
        # db.drop_all() # Optional: uncomment to drop tables first
        db.create_all()
        print('Database initialized and tables created.')

# --- API Endpoints / Routes ---

@app.route('/')
def home():
    """Renders the main HTML page, passing username if logged in."""
    logged_in_username = session.get('username', None)
    print(f"Rendering home page. Logged in user: {logged_in_username}")
    return render_template('index.html', username=logged_in_username)

@app.route('/api/test')
def api_test():
    """Returns a simple JSON message to confirm the API is reachable."""
    return jsonify({"message": "API is working!"})

# --- Registration Endpoint ---
@app.route('/register', methods=['POST'])
def register():
    """Handles POST requests for user registration."""
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"--- Registration Attempt ---")
        print(f"Username: '{username}', Password Provided: {'Yes' if password else 'No'}")

        if not username or not password:
            print("Registration failed: Missing username or password.")
            return jsonify({"status": "error", "message": "Username and password are required."}), 400

        print(f"Checking if user '{username}' exists...")
        # Ensure we query within context
        with app.app_context():
             existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            print(f"Registration failed: User '{username}' already exists.")
            return jsonify({"status": "error", "message": "Username already taken. Please choose another."}), 409

        print(f"Creating new user object for '{username}'...")
        new_user = User(username=username)
        print(f"Setting password for '{username}'...")
        new_user.set_password(password)

        print(f"Adding user '{username}' to session...")
        db.session.add(new_user)
        print(f"Committing session for user '{username}'...")
        db.session.commit()

        print(f"User registered successfully: {username}")
        return jsonify({"status": "success", "message": f"User '{username}' registered successfully!"}), 201

    except Exception as e:
        db.session.rollback()
        print(f"!!! Critical Error during registration: {e}")
        traceback.print_exc() # Print detailed error traceback
        return jsonify({"status": "error", "message": "An internal server error occurred during registration."}), 500


# --- Login Endpoint ---
@app.route('/login', methods=['POST'])
def login():
    """Handles POST requests from the login form and sets session."""
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"--- Login Attempt ---")
        print(f"Username received: '{username}'")

        if not username or not password:
             print("Login failed: Missing username or password.")
             return jsonify({"status": "error", "message": "Missing username or password."}), 400

        print(f"Querying database for username: '{username}'")
        # Ensure query runs within context
        with app.app_context():
             user = User.query.filter_by(username=username).first()

        if not user:
            print(f"Login failed: User '{username}' not found.")
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401

        print(f"User found: {user}")
        password_match = user.check_password(password)
        print(f"Password check result: {password_match}")

        if password_match:
            session['username'] = user.username
            session['user_id'] = user.id
            print(f"Login successful, session set for user: {username}")
            return jsonify({"status": "success", "message": f"Login successful for {username}.", "username": user.username})
        else:
            print(f"Login failed: Incorrect password for user '{username}'.")
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401

    except Exception as e:
        print(f"Error during login: {e}")
        traceback.print_exc() # Print detailed error traceback
        return jsonify({"status": "error", "message": "An internal server error occurred during login."}), 500

# --- Logout Endpoint ---
@app.route('/logout')
def logout():
    """Clears the session to log the user out."""
    session.pop('username', None)
    session.pop('user_id', None)
    print("User logged out, session cleared.")
    return redirect(url_for('home'))


# --- Run the App (Only for local development) ---
# Gunicorn runs the app in production via Procfile
if __name__ == '__main__':
    # Run 'flask init-db' manually in terminal if needed locally.
    app.run(debug=True, host='0.0.0.0', port=5000)
