import os
import secrets
import datetime
from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # Make sure Migrate is imported
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
migrate = Migrate(app, db) # Initialize Flask-Migrate

# --- Database Model Definitions ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient') # Added role ('patient', 'caregiver', 'admin')

    # --- Relationships ---
    # If User is a Patient, who is their caregiver? (One-to-Many from Caregiver's perspective)
    caregiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Link to caregiver (another User)
    # If User is a Caregiver, which patients are they assigned? (Backref defined below)
    assigned_patients = db.relationship('User', backref=db.backref('caregiver', remote_side=[id]), lazy='dynamic')

    # Existing relationships
    health_records = db.relationship('HealthRecord', backref='patient', lazy='dynamic') # Changed backref name
    notifications = db.relationship('Notification', backref='recipient', lazy='dynamic') # Changed backref name
    medications = db.relationship('Medication', backref='patient', lazy='dynamic') # Added medication relationship

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} (Role: {self.role})>'

class HealthRecord(db.Model):
    __tablename__ = 'health_records'
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(50), nullable=False)
    value1 = db.Column(db.String(50), nullable=False)
    value2 = db.Column(db.String(50), nullable=True)
    unit = db.Column(db.String(20), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Link to the User table (patient)

    def __repr__(self):
        # Access patient username via backref
        return f'<HealthRecord {self.record_type} for User {self.patient.username if self.patient else self.user_id}>'

class Meal(db.Model):
    # No changes needed here for now, but could link to user later
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
    notification_type = db.Column(db.String(50), default='general') # e.g., 'general', 'medication_reminder', 'appointment'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Link to the User table (recipient)

    def __repr__(self):
         return f'<Notification for User {self.recipient.username if self.recipient else self.user_id}>'

# --- NEW: Medication Model ---
class Medication(db.Model):
    __tablename__ = 'medications'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    dosage = db.Column(db.String(100), nullable=True) # e.g., "10mg", "1 tablet"
    frequency = db.Column(db.String(100), nullable=True) # e.g., "Twice daily", "As needed"
    current_quantity = db.Column(db.Integer, nullable=True) # Optional: track quantity
    low_stock_threshold = db.Column(db.Integer, nullable=True) # Optional: quantity level to trigger alert
    refill_due_date = db.Column(db.Date, nullable=True) # Optional: track refill date
    notes = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Link to the User table (patient)

    def __repr__(self):
        return f'<Medication {self.name} for User {self.patient.username if self.patient else self.user_id}>'


# --- Database Initialization Command ---
# Use `flask db upgrade` from terminal
@app.cli.command('init-db')
def init_db_command():
    """DEPRECATED by Flask-Migrate. Use 'flask db upgrade'."""
    print("This command is deprecated. Use 'flask db upgrade' to apply migrations.")
    # with app.app_context():
    #     print("Initializing the database...")
    #     db.drop_all()
    #     db.create_all()
    #     print('Database initialized and tables created.')

# --- API Endpoints / Routes ---

@app.route('/')
def home():
    """Renders the main HTML page, passing username if logged in."""
    logged_in_username = session.get('username', None)
    user_role = None
    assigned_caregiver_name = None
    if logged_in_username:
        with app.app_context():
            # Fetch user details including role and caregiver if applicable
            user = User.query.filter_by(username=logged_in_username).first()
            if user:
                user_role = user.role
                if user.role == 'patient' and user.caregiver:
                    assigned_caregiver_name = user.caregiver.username
                elif user.role == 'caregiver':
                    # Logic to get caregiver's own info if needed
                    pass

    print(f"Rendering home page. User: {logged_in_username}, Role: {user_role}, Caregiver: {assigned_caregiver_name}")
    return render_template('index.html',
                           username=logged_in_username,
                           role=user_role,
                           assigned_caregiver=assigned_caregiver_name)


@app.route('/api/test')
def api_test():
    return jsonify({"message": "API is working!"})

@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'patient') # Default to patient if not specified

        print(f"--- Registration Attempt ---")
        print(f"Username: '{username}', Role: '{role}', Password Provided: {'Yes' if password else 'No'}")

        if not username or not password:
            return jsonify({"status": "error", "message": "Username and password are required."}), 400
        if role not in ['patient', 'caregiver']: # Basic role validation
             return jsonify({"status": "error", "message": "Invalid role specified."}), 400

        with app.app_context(): existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"status": "error", "message": "Username already taken."}), 409

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        print(f"User registered: {username} with role {role}")
        return jsonify({"status": "success", "message": f"User '{username}' registered successfully as {role}!"}), 201

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
        print(f"--- Login Attempt ---")
        print(f"Username received: '{username}'")

        if not username or not password:
             return jsonify({"status": "error", "message": "Missing username or password."}), 400

        with app.app_context(): user = User.query.filter_by(username=username).first()

        if not user:
            print(f"Login failed: User '{username}' not found.")
            return jsonify({"status": "error", "message": "Invalid username or password."}), 401

        password_match = user.check_password(password)
        print(f"Password check result: {password_match}")

        if password_match:
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role # Store role in session
            print(f"Login successful, session set for user: {username}, role: {user.role}")
            return jsonify({"status": "success", "message": f"Login successful for {username}.", "username": user.username, "role": user.role})
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
    session.pop('role', None) # Clear role from session
    print("User logged out, session cleared.")
    return redirect(url_for('home'))

# --- Health Record Endpoint ---
@app.route('/api/health-records', methods=['POST'])
def add_health_record():
    if 'user_id' not in session: return jsonify({"status": "error", "message": "Unauthorized access."}), 401

    try:
        # Determine whose record to add (self for patient, selected patient for caregiver)
        # For now, assume logged-in user is adding their own record
        patient_user_id = session['user_id']
        # TODO: Add logic here if a caregiver is adding for a patient

        record_type = request.form.get('record_type')
        value1 = request.form.get('value1')
        value2 = request.form.get('value2')
        unit = request.form.get('unit')

        print(f"--- Add Health Record Attempt ---")
        print(f"User ID (Patient): {patient_user_id}, Type: {record_type}, V1: {value1}, V2: {value2}, Unit: {unit}")

        if not record_type or not value1:
            return jsonify({"status": "error", "message": "Record type and primary value are required."}), 400

        new_record = HealthRecord(
            user_id=patient_user_id, # Link to the correct patient
            record_type=record_type,
            value1=value1,
            value2=value2,
            unit=unit
        )
        db.session.add(new_record)
        db.session.commit()

        print(f"Health record added successfully for user_id: {patient_user_id}")
        # TODO: Optionally fetch and return updated health stats for the dashboard
        return jsonify({"status": "success", "message": f"{record_type} record added successfully."}), 201

    except Exception as e:
        db.session.rollback()
        print(f"!!! Critical Error adding health record: {e}")
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Internal server error while adding record."}), 500

# --- Placeholder API Endpoints ---
# These need to be implemented fully later

@app.route('/api/my-patients')
def get_my_patients():
    if session.get('role') != 'caregiver': return jsonify({"error": "Unauthorized"}), 401
    # TODO: Query database for patients assigned to session['user_id']
    # Example simulation:
    simulated_patients = [ {"id": 101, "name": "Alice Smith"}, {"id": 102, "name": "Bob Johnson"} ]
    return jsonify(simulated_patients)

@app.route('/api/patient/<int:patient_id>/dashboard-data')
def get_patient_dashboard(patient_id):
    if 'user_id' not in session: return jsonify({"error": "Unauthorized"}), 401
    # TODO: Check if logged-in user (caregiver or patient themselves) is allowed to view patient_id's data
    # TODO: Query HealthRecord, Meal, Notification for the patient_id
    # Example simulation:
    print(f"Fetching dashboard data for patient_id: {patient_id}")
    # Return data similar to the frontend simulation structure
    simulated_data = {
        "health": {"bp": "125/85 mmHg", "sugar": "105 mg/dL", "hr": "70 bpm", "updated": "Now"},
        "meals": {"breakfast": ["Simulated Fetched Oatmeal"], "lunch": ["Simulated Fetched Salad"], "dinner": ["Simulated Fetched Chicken"]},
        "notifications": [{"id": 10, "msg": "Simulated fetched notification"}]
    }
    return jsonify(simulated_data)

@app.route('/api/notifications')
def get_notifications():
     if 'user_id' not in session: return jsonify({"error": "Unauthorized"}), 401
     user_id = session['user_id']
     # TODO: Query Notification table for user_id
     # TODO: Implement logic to check for medication renewals and add notifications if needed
     # Example simulation:
     simulated_notifications = [
         {"id": 20, "msg": "Medication 'Lisinopril' may need renewal soon.", "type": "medication_reminder"},
         {"id": 21, "msg": "Appointment reminder: Dr. Smith tomorrow."}
     ]
     return jsonify(simulated_notifications)


# --- Run the App (Only for local development) ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
