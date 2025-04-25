import os
import secrets
import datetime
from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
# Import Migrate
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import click
import traceback

# --- App and Database Configuration ---

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder='templates')

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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
if not os.environ.get('SECRET_KEY'):
    print("Warning: SECRET_KEY environment variable not set. Using temporary key.")

db = SQLAlchemy(app)
# Initialize Flask-Migrate
migrate = Migrate(app, db)

# --- REMOVE TEMPORARY CODE TO CREATE TABLES ---
# Ensure the temporary db.create_all() block is removed from here


# --- Database Model Definitions ---
# (User, HealthRecord, Meal, Notification classes remain the same as before)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    health_records = db.relationship('HealthRecord', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class HealthRecord(db.Model):
    __tablename__ = 'health_records'
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(50), nullable=False)
    value1 = db.Column(db.String(50), nullable=False)
    value2 = db.Column(db.String(50), nullable=True)
    unit = db.Column(db.String(20), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<HealthRecord {self.record_type} for User {self.user_id}>'

class Meal(db.Model):
    __tablename__ = 'meals'
    id = db.Column(db.Integer, primary_key=True)
    meal_type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Meal {self.name} ({self.meal_type})>'

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<Notification for User {self.user_id}>'

# --- Database Initialization Command (No longer needed for table creation) ---
# Flask-Migrate handles this via 'flask db upgrade'
# You can remove the init-db command if you like, or keep it for local use.
# @app.cli.command('init-db')
# def init_db_command():
#     """DEPRECATED by Flask-Migrate"""
#     with app.app_context():
#         print("Initializing the database...")
#         db.create_all()
#         print('Database initialized and tables created.')

# --- API Endpoints / Routes ---
# (All your routes like @app.route('/'), @app.route('/login'), etc. remain the same)
@app.route('/')
def home():
    logged_in_username = session.get('username', None)
    print(f"Rendering home page. Logged in user: {logged_in_username}")
    return render_template('index.html', username=logged_in_username)

@app.route('/api/test')
def api_test():
    return jsonify({"message": "API is working!"})

@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password: return jsonify({"status": "error", "message": "Username and password are required."}), 400
        with app.app_context(): existing_user = User.query.filter_by(username=username).first()
        if existing_user: return jsonify({"status": "error", "message": "Username already taken."}), 409
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        print(f"User registered: {username}")
        return jsonify({"status": "success", "message": f"User '{username}' registered successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"!!! Critical Error during registration: {e}")
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Internal server error during registration."}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password: return jsonify({"status": "error", "message": "Missing username or password."}), 400
        with app.app_context(): user = User.query.filter_by(username=username).first()
        if not user:
            print(f"Login failed: User '{username}' not found.")
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401
        password_match = user.check_password(password)
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
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Internal server error during login."}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    print("User logged out, session cleared.")
    return redirect(url_for('home'))

# --- Run the App (Only for local development) ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
