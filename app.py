import os
import secrets
from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --- App and Database Configuration (Updated for Deployment) ---

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder='templates')

# --- Database Configuration ---
# Use Render's DATABASE_URL environment variable if available, otherwise fallback to SQLite
# Render automatically sets DATABASE_URL for its PostgreSQL service
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    # Render provides postgresql URLs, SQLAlchemy needs postgresql://
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or \
                                        'sqlite:///' + os.path.join(basedir,
                                                                    'elderly_care_dev.db')  # Use a different name for local dev DB

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Secret Key Configuration ---
# Use Render's SECRET_KEY environment variable or generate one
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
# IMPORTANT: Set the SECRET_KEY environment variable in Render's settings!

db = SQLAlchemy(app)


# --- Database Model Definition ---
# (User class definition remains the same as before)
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


# --- Create Database Tables ---
# It's generally better to run this manually or use migrations (like Flask-Migrate)
# after deploying, rather than before every request in production.
# You can run this once via Render's shell after the first deploy if needed.
# Commenting out the automatic creation for now.
# with app.app_context():
#     db.create_all()
#   print("Database tables checked/created.")

# --- API Endpoints / Routes ---
# (All your routes like @app.route('/'), @app.route('/login'), etc. remain the same)
@app.route('/')
def home():
    logged_in_username = session.get('username', None)
    return render_template('index.html', username=logged_in_username)


@app.route('/api/test')
def api_test():
    return jsonify({"message": "API is working!"})


@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password: return jsonify(
            {"status": "error", "message": "Username and password are required."}), 400
        existing_user = User.query.filter_by(username=username).first()
        if existing_user: return jsonify({"status": "error", "message": "Username already taken."}), 409
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        print(f"User registered: {username}")
        return jsonify({"status": "success", "message": f"User '{username}' registered successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")
        return jsonify({"status": "error", "message": "Internal server error."}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password: return jsonify(
            {"status": "error", "message": "Missing username or password."}), 400
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = user.username
            session['user_id'] = user.id
            print(f"Login successful for user: {username}")
            return jsonify(
                {"status": "success", "message": f"Login successful for {username}.", "username": user.username})
        else:
            print(f"Login failed for user: {username}")
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({"status": "error", "message": "Internal server error."}), 500


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    print("User logged out, session cleared.")
    return redirect(url_for('home'))


# --- Run the App (Only for local development) ---
# Gunicorn will run the app in production via the Procfile
# The if __name__ == '__main__': block is NOT needed for Render deployment
# but keep it for running locally with `python app.py`
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

