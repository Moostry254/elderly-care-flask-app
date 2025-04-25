import os
import secrets
import datetime # Import datetime for timestamps
from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
# Import Migrate
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import click
import traceback # Import traceback for better error logging

# --- App and Database Configuration ---

basedir = os.path.abspath(os.path.dirname(__file__))
# Ensure Flask looks for the 'templates' folder
app = Flask(__name__, template_folder='templates')

# --- Database Configuration ---
database_url = os.environ.get('DATABASE_URL')
final_db_uri = None

if database_url:
    print("DATABASE_URL environment variable found.")
    # Render provides postgresql URLs, SQLAlchemy needs postgresql://
    if database_url.startswith("postgres://"):
        final_db_uri = database_url.replace("postgres://", "postgresql://", 1)
        print(f"Using Render PostgreSQL URI: {final_db_uri}")
    else:
        final_db_uri = database_url
        print(f"Using DATABASE_URL directly: {final_db_uri}")
else:
    print("DATABASE_URL environment variable NOT found. Falling back to local SQLite.")
    # Use a different name for local dev DB to avoid confusion
    sqlite_path = os.path.join(basedir, 'local_dev.db')
    final_db_uri = 'sqlite:///' + sqlite_path
    print(f"Using local SQLite URI: {final_db_uri}")


app.config['SQLALCHEMY_DATABASE_URI'] = final_db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Secret Key Configuration ---
# Use Render's SECRET_KEY environment variable or generate one
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
if not os.environ.get('SECRET_KEY'):
    print("Warning: SECRET_KEY environment variable not set. Using temporary key.")

# Initialize SQLAlchemy
db = SQLAlchemy(app)
# Initialize Flask-Migrate
migrate = Migrate(app, db)

# --- Database Model Definitions ---

class User(db.Model):
    __tablename__ = 'users' # Explicit table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # === NEW: Added role column ===
    role = db.Column(db.String(20), nullable=False, default='patient') # e.g., 'patient', 'caregiver', 'admin'

    # === NEW: Relationships for Caregiver/Patient assignment ===
    # If User is a Patient, this links to their assigned caregiver's ID
    caregiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    # If User is a Caregiver, this provides a list of patients assigned to them
    # 'User' refers back to this same User model
    # backref='caregiver' allows accessing patient.caregiver
    # remote_side=[id] is needed for self-referential one-to-many
    # lazy='dynamic' means assigned_patients will be a query object, not loaded immediately
    assigned_patients = db.relationship('User',
                                        backref=db.backref('caregiver', remote_side=[id]),
                                        lazy='dynamic',
                                        foreign_keys=[caregiver_id]) # Specify the foreign key column

    # Existing relationships (updated backref names for clarity)
    health_records = db.relationship('HealthRecord', backref='patient', lazy='dynamic')
    notifications = db.relationship('Notification', backref='recipient', lazy='dynamic')
    # === NEW: Added relationship to Medications ===
    medications = db.relationship('Medication', backref='patient', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} (Role: {self.role})>'

class HealthRecord(db.Model):
    __tablename__ = 'health_records'
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(50), nullable=False) # e.g., 'Blood Pressure'
    value1 = db.Column(db.String(50), nullable=False) # e.g., Systolic
    value2 = db.Column(db.String(50), nullable=True) # e.g., Diastolic
    unit = db.Column(db.String(20), nullable=True) # e.g., 'mmHg'
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Link to the User table (patient)

    def __repr__(self):
        # Access patient username via backref
        return f'<HealthRecord {self.record_type} for User {self.patient.username if self.patient else self.user_id}>'

class Meal(db.Model):
    # No changes needed here for now, but could link to user later
    __tablename__ = 'meals'
    id = db.Column(db.Integer, primary_key=True)
    meal_type = db.Column(db.String(50), nullable=False) # e.g., 'Breakfast'
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


# --- API Endpoints / Routes ---

@app.route('/')
def home():
    """Renders the main HTML page, passing username, role, and caregiver if logged in."""
    logged_in_username = session.get('username', None)
    user_role = None
    assigned_caregiver_name = None
    if logged_in_username:
        with app.app_context():
            # Fetch user details including role and caregiver if applicable
            user = User.query.filter_by(username=logged_in_username).first()
            if user:
                user_role = user.role
                # Check if the user is a patient and has a caregiver assigned
                if user.role == 'patient' and user.caregiver:
                    assigned_caregiver_name = user.caregiver.username

    print(f"Rendering home page. User: {logged_in_username}, Role: {user_role}, Caregiver: {assigned_caregiver_name}")
    # Pass all relevant variables to the template
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
        role = request.form.get('role', 'patient')

        print(f"--- Registration Attempt ---")
        print(f"Username: '{username}', Role: '{role}', Password Provided: {'Yes' if password else 'No'}")

        if not username or not password:
            return jsonify({"status": "error", "message": "Username and password are required."}), 400
        if role not in ['patient', 'caregiver']:
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
        patient_user_id = session['user_id'] # Default to self
        if session.get('role') == 'caregiver':
             submitted_patient_id = request.form.get('patient_id')
             if submitted_patient_id:
                 # TODO: IMPORTANT Security Check: Verify this caregiver is allowed to add records for submitted_patient_id
                 print(f"Caregiver {session['username']} adding record for patient ID {submitted_patient_id}")
                 patient_user_id = submitted_patient_id # Use the submitted ID
             else:
                 print(f"Caregiver {session['username']} trying to add record without patient_id.")
                 return jsonify({"status": "error", "message": "Caregiver must specify patient ID."}), 400


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
        return jsonify({"status": "success", "message": f"{record_type} record added successfully."}), 201

    except Exception as e:
        db.session.rollback()
        print(f"!!! Critical Error adding health record: {e}")
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Internal server error while adding record."}), 500

# --- Placeholder API Endpoints ---

@app.route('/api/my-patients')
def get_my_patients():
    if session.get('role') != 'caregiver': return jsonify({"error": "Unauthorized"}), 401
    caregiver_id = session.get('user_id')
    if not caregiver_id: return jsonify({"error": "Unauthorized"}), 401

    with app.app_context():
        patients = User.query.filter_by(caregiver_id=caregiver_id, role='patient').all()
    patient_list = [{"id": p.id, "name": p.username} for p in patients]
    print(f"Returning assigned patients for caregiver {session.get('username')}: {patient_list}")
    return jsonify(patient_list)

@app.route('/api/patient/<int:patient_id>/dashboard-data')
def get_patient_dashboard(patient_id):
    if 'user_id' not in session: return jsonify({"error": "Unauthorized"}), 401
    logged_in_user_id = session['user_id']
    logged_in_user_role = session.get('role')

    with app.app_context():
        patient = User.query.get(patient_id)
        if not patient or patient.role != 'patient':
            return jsonify({"error": "Patient not found"}), 404
        is_authorized = (logged_in_user_id == patient.id) or \
                        (logged_in_user_role == 'caregiver' and patient.caregiver_id == logged_in_user_id)
        if not is_authorized:
            return jsonify({"error": "Forbidden"}), 403

        # TODO: Query REAL data for this patient_id
        latest_health_list = HealthRecord.query.filter_by(user_id=patient_id).order_by(HealthRecord.timestamp.desc()).limit(5).all() # Get last 5
        # Format health data (simplified example, only shows latest of each type)
        health_summary = {}
        latest_update_time = "N/A"
        for record in sorted(latest_health_list, key=lambda x: x.timestamp, reverse=True): # Process latest first
            if latest_update_time == "N/A": latest_update_time = record.timestamp.strftime("%Y-%m-%d %H:%M")
            if record.record_type == 'Blood Pressure' and 'bp' not in health_summary:
                health_summary['bp'] = f"{record.value1}/{record.value2} {record.unit or 'mmHg'}"
            elif record.record_type == 'Blood Sugar' and 'sugar' not in health_summary:
                 health_summary['sugar'] = f"{record.value1} {record.unit or 'mg/dL'}"
            elif record.record_type == 'Heart Rate' and 'hr' not in health_summary:
                 health_summary['hr'] = f"{record.value1} {record.unit or 'bpm'}"
        health_summary['updated'] = latest_update_time


        # TODO: Query Meal data
        meals_summary = {"breakfast": ["Fetched Meal 1"], "lunch": ["Fetched Meal 2"], "dinner": ["Fetched Meal 3"]}

        # TODO: Query Notification data
        notifications_list = Notification.query.filter_by(user_id=patient_id, is_read=False).order_by(Notification.timestamp.desc()).all()
        notifications_summary = [{"id": n.id, "msg": n.message, "type": n.notification_type} for n in notifications_list]


    print(f"Fetching dashboard data for authorized patient_id: {patient_id}")
    final_data = {
        "health": health_summary,
        "meals": meals_summary,
        "notifications": notifications_summary
    }
    return jsonify(final_data)

@app.route('/api/notifications')
def get_notifications():
     if 'user_id' not in session: return jsonify({"error": "Unauthorized"}), 401
     user_id = session['user_id']
     user_role = session.get('role')

     # TODO: Implement real notification fetching and medication checks
     simulated_notifications = []
     if user_role == 'patient':
         simulated_notifications = [
             {"id": 20, "msg": "Medication 'Amlodipine' may need renewal soon.", "type": "medication_reminder"},
             {"id": 21, "msg": "Appointment reminder: Dr. Lee Tuesday."}
         ]
     elif user_role == 'caregiver':
          simulated_notifications = [
             {"id": 40, "msg": "Check patient Alice Smith's BP.", "type": "task"},
             {"id": 41, "msg": "Patient Bob Johnson reported low stock on Metformin.", "type": "medication_reminder"}
         ]

     return jsonify(simulated_notifications)


# --- Run the App (Only for local development) ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

