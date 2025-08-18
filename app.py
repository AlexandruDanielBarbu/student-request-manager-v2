# Imports
import os
import csv
import io
import datetime

from datetime         import datetime, timezone
from io               import StringIO

from flask            import Flask, render_template, session, redirect, url_for, request, flash, send_file
from flask_scss       import Scss
from flask_sqlalchemy import SQLAlchemy
from flask_migrate    import Migrate
from flask_login      import LoginManager, current_user, login_required, login_user, logout_user, UserMixin

from sqlalchemy       import desc
from sqlalchemy.exc   import IntegrityError
from enum             import Enum
from functools        import wraps

from reportlab.pdfgen        import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units     import cm
from reportlab.platypus      import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles    import getSampleStyleSheet

class RoleType(Enum):
    ADMIN    = 'ADMIN'
    EMPLOYEE = 'EMPLOYEE'
    STUDENT  = 'STUDENT'

# Custom decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If not logged in, redirect to login page
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        # If not admin then deny
        if current_user.role.name != RoleType.ADMIN.value:
            return 'You are not allowed here!', 403

        # All is good
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If not logged in, redirect to login page
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        # If not student then deny
        if current_user.role.name != RoleType.STUDENT.value:
            return 'You are not allowed here!', 403

        # All is good
        return f(*args, **kwargs)
    return decorated_function

def employee_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If not logged in, redirect to login page
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        # If not employee then deny
        if current_user.role.name != RoleType.EMPLOYEE.value:
            return 'You are not allowed here!', 403

        # All is good
        return f(*args, **kwargs)
    return decorated_function

# App
app = Flask(__name__)
Scss(app)

# Database setup
app.config['SECRET_KEY'] = 'something'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Tables
class Role(db.Model):
    __tablename__ = 'roles'

    id    = db.Column(db.Integer, primary_key=True)
    name  = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return f"<{self.name}>"

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)

    role_id      = db.Column(db.Integer, db.ForeignKey('roles.id'))
    student_info = db.relationship('Student', foreign_keys='Student.user_id', backref='user', uselist=False)
    students_under_care = db.relationship('Student', foreign_keys='Student.responsible_employee_id', backref='responsible_employee', lazy='dynamic')

    def __repr__(self):
        return f"<{self.username}>"

    def check_password(self, password):
        return self.password == password

class Student(db.Model):
    __tablename__ = 'students'

    id              = db.Column(db.Integer, primary_key=True)
    faculty         = db.Column(db.String(100), nullable=True)
    domain          = db.Column(db.String(100), nullable=True)
    start_year      = db.Column(db.Integer, nullable=True)
    graduation_year = db.Column(db.Integer, nullable=True)

    user_id         = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_user_id'), unique=True, nullable=False)
    responsible_employee_id = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_students_responsible_employee'), nullable=True)

    def __repr__(self):
        return f"<Student info for {self.user.username}>"

class Log(db.Model):
    __tablename__ = 'logs'

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    document_type = db.Column(db.String(100), nullable=False)
    requested_at  = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    served_at     = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    user          = db.relationship('User', backref='logs')

# Routes
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role.name == RoleType.ADMIN.value:
        return redirect(url_for('admin_dashboard'))
    elif current_user.role.name == RoleType.EMPLOYEE.value:
        return redirect(url_for('employee_dashboard'))
    elif current_user.role.name == RoleType.STUDENT.value:
        return redirect(url_for('student_dashboard'))
    else:
        return 'Unauthorized'

@app.route('/admin-dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    # We have some data from the forms to handle
    if request.method == 'POST':
        if 'add_user' in request.form:
            # Get data from the form
            email    = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            role     = request.form.get('role')

            try:
                # Checking if ROLE exists
                generic_role = Role.query.filter_by(name=role).first()
                if not generic_role:
                    a_role = Role(name=role)
                    db.session.add(a_role)
                    db.session.commit()
                    print(f"{a_role} was creted")
                else:
                    print(f"{role} already exists")

                # Checking if the user exists already
                role_obj = Role.query.filter_by(name=role).first()
                user = User.query.filter_by(username=username).first()
                if not user:
                    new_user = User(
                        username = username,
                        password = password,
                        email    = email,
                        role     = role_obj
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    print("User created")
                    return redirect(url_for('admin_dashboard'))

                else:
                    print("User already exists")
                    return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                print(f"ERROR: {e}")
                return redirect(url_for('admin_dashboard'))

        if 'delete_user' in request.form:
                username = request.form.get('username')

                try:
                    user_to_delete = User.query.filter_by(username=username).first()

                    # Self deletion check
                    if username == current_user.username:
                        flash("You cannot delete yourself!", 'error')
                        return redirect(url_for('admin_dashboard'))

                    # Non existent user deletion check
                    if user_to_delete:
                        db.session.delete(user_to_delete)
                        db.session.commit()
                        return redirect(url_for('admin_dashboard'))
                    else:
                        print("This user does not exist therefore it cannot be deleted!")
                        return redirect(url_for('admin_dashboard'))

                except Exception as e:
                    db.session.rollback()
                    print(f"ERROR: {e}")

        if 'csv_add_user' in request.form:
            try:
                csv_file = request.files.get('csv_file')

                # Test .csv file conditions
                if not csv_file or not csv_file.filename.endswith('.csv'):
                    flash('Please upload a valid CSV file for user creation.', 'error')
                    return redirect(url_for('admin_dashboard'))
                else:
                    # Work the .csv magic
                    csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                    csv_reader = csv.DictReader(csv_text, delimiter=',')
                    created_count = 0

                    for row in csv_reader:
                        # Extract data from the CSV row
                        username = row.get('username')
                        email = row.get('email')
                        password = row.get('password')
                        role_name = row.get('role')

                        # Skip if any essential data is missing
                        if not all([username, email, password, role_name]):
                            print(f"Skipping row with missing data: {row}")
                            continue

                        # Check if a user with this username or email already exists
                        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
                        if existing_user:
                            print(f"User with username '{username}' or email '{email}' already exists. Skipping.")
                            continue

                        # Find or create the role
                        role_obj = Role.query.filter_by(name=role_name).first()
                        if not role_obj:
                            role_obj = Role(name=role_name)
                            db.session.add(role_obj)
                            db.session.commit()

                        # Create and save the new user
                        new_user = User(
                            username=username,
                            email=email,
                            password=password,
                            role=role_obj
                        )

                        db.session.add(new_user)
                        created_count += 1

                    db.session.commit()
                    flash(f'{created_count} users were successfully created from the CSV.', 'success')
                    return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during bulk user creation: {e}', 'error')
                return redirect(url_for('admin_dashboard'))

        if 'csv_delete_user' in  request.form:
            try:
                csv_file = request.files.get('csv_file')

                # Test .csv file conditions
                if not csv_file or not csv_file.filename.endswith('.csv'):
                    flash('Please upload a valid CSV file for user creation.', 'error')
                    return redirect(url_for('admin_dashboard'))
                else:
                    # Work the .csv magic
                    csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                    csv_reader = csv.DictReader(csv_text, delimiter=',')
                    deleted_count = 0

                    for row in csv_reader:
                        # Extract data from the CSV row
                        username = row.get('username')

                        # Self deletion check
                        if username == current_user.username:
                            flash("You cannot delete yourself!", 'error')
                            continue

                        # Check if a user with this username or email already exists
                        existing_user = User.query.filter((User.username == username)).first()
                        if not existing_user:
                            print(f"No such user to delete!")
                            continue

                        # Delete the user
                        db.session.delete(existing_user)
                        deleted_count += 1

                    db.session.commit()
                    flash(f'{deleted_count} users were successfully deleted from the CSV.', 'success')
                    return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during bulk user deletion: {e}', 'error')
                return redirect(url_for('admin_dashboard'))

        if 'logout' in request.form:
            return redirect(url_for('logout'))

        if 'join_students' in request.form:
            # Get form data
            student_name = request.form.get('student_username')
            employee_name = request.form.get('employee_username')

            try:
                # Find the users
                student_user  = User.query.filter_by(username=student_name).first()
                employee_user = User.query.filter_by(username=employee_name).first()

                # Get the roles
                student_role = Role.query.filter_by(name='STUDENT').first()
                employee_role = Role.query.filter_by(name='EMPLOYEE').first()

                # Verify users
                if not student_user or student_user.role != student_role:
                    flash(f'Error: User "{student_name}" not found or is not a student.', 'error')
                    return redirect(url_for('admin_dashboard'))

                if not employee_user or employee_user.role != employee_role:
                    flash(f'Error: User "{employee_name}" not found or is not an employee.', 'error')
                    return redirect(url_for('admin_dashboard'))

                # Get student specific data
                student_data = Student.query.filter_by(user=student_user).first()

                if not student_data:
                    student_data = Student(user=student_user)
                    db.session.add(student_data)

                student_data.responsible_employee = employee_user

                db.session.commit()
                print(f"Added {student_name} to {employee_name}!")

            except Exception as e:
                db.session.rollback()
                print(f"ERROR: {e}")
                return redirect(url_for('admin_dashboard'))

        if 'csv_join_students' in request.form:
            try:
                csv_file = request.files.get('csv_file')

                # Test .csv file conditions
                if not csv_file or not csv_file.filename.endswith('.csv'):
                    flash('Please upload a valid CSV file for user creation.', 'error')
                    return redirect(url_for('admin_dashboard'))
                else:
                    # Work the .csv magic
                    csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                    csv_reader = csv.DictReader(csv_text, delimiter=',')
                    succes_count = 0

                    for row in csv_reader:
                        # Extract data from the CSV row
                        student_username = row.get('student_username')
                        employee_username = row.get('employee_username')

                        # Skip if any essential data is missing
                        if not all([student_username, employee_username]):
                            print(f"Skipping row with missing data: {row}")
                            continue

                        # Find the users
                        student_user = User.query.filter((User.username == student_username)).first()
                        employee_user = User.query.filter((User.username == employee_username)).first()

                        # Check if a user with this username exists
                        if not student_user or not employee_user:
                            print(f"'{student_username}' or '{employee_username}' does not exist. Skipping.")
                            continue

                        # Asign the student to the employee
                        try:
                            # Get the roles
                            student_role = Role.query.filter_by(name='STUDENT').first()
                            employee_role = Role.query.filter_by(name='EMPLOYEE').first()

                            # Verify users
                            if not student_user or student_user.role != student_role:
                                flash(f'Error: User "{student_name}" not found or is not a student.', 'error')
                                return redirect(url_for('admin_dashboard'))

                            if not employee_user or employee_user.role != employee_role:
                                flash(f'Error: User "{employee_name}" not found or is not an employee.', 'error')
                                return redirect(url_for('admin_dashboard'))

                            # Get student specific data
                            student_data = Student.query.filter_by(user=student_user).first()

                            if not student_data:
                                student_data = Student(user=student_user)
                                db.session.add(student_data)

                            student_data.responsible_employee = employee_user
                            print(f"Added {student_name} to {employee_name}!")

                            succes_count += 1

                        except Exception as e:
                            db.session.rollback()
                            print(f"ERROR: {e}")
                            return redirect(url_for('admin_dashboard'))

                    db.session.commit()
                    flash(f'{succes_count} students were successfully asigned from the CSV.', 'success')
                    return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during bulk user creation: {e}', 'error')
                return redirect(url_for('admin_dashboard'))


    # Render all users in a table
    all_users = User.query.all()
    return render_template('admin_dashboard.html', users=all_users, now_user=current_user)

@app.route('/employee-dashboard', methods=['GET', 'POST'])
@login_required
@employee_required
def employee_dashboard():
    if request.method == 'POST':
        if 'logout' in request.form:
            return redirect(url_for('logout'))

        if 'update_student' in request.form:
            student_username = request.form.get('username')
            faculty          = request.form.get('faculty')
            domain           = request.form.get('domain')
            start_year       = request.form.get('start_year')
            graduation_year  = request.form.get('graduation_year')

            if not faculty or not domain or not start_year or not graduation_year:
                flash(f"Please complete the entire form!")
                return redirect(url_for('employee_dashboard'))

            student_user = User.query.filter_by(username=student_username).first()
            if not student_user:
                flash("The selected user does not exist!")
                return redirect(url_for('employee_dashboard'))

            student_data = student_user.student_info
            if not student_data:
                student_data = Student(user_id=student_user.id)
                db.session.add(student_data)

            # Update user data here
            student_data.faculty = faculty
            student_data.domain = domain

            try:
                if start_year:
                    student_data.start_year = int(start_year)
                if graduation_year:
                    student_data.graduation_year = int(graduation_year)
            except ValueError:
                flash("Start year and graduation year must be valid numbers.")
                return redirect(url_for('employee_dashboard'))

            try:
                db.session.commit()
                flash(f"Student data for {student_username} has been updated successfully!")
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred while updating student data: {e}")

        if 'update_student_csv' in request.form:
            # Assuming this is part of your employee_dashboard route
            try:
                csv_file = request.files.get('csv_file')

                if not csv_file or not csv_file.filename.endswith('.csv'):
                    flash('Please upload a valid CSV file for student updates.', 'error')
                    return redirect(url_for('employee_dashboard'))

                csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                csv_reader = csv.DictReader(csv_text, delimiter=',')
                updated_count = 0

                for row in csv_reader:
                    username        = row.get('username')
                    faculty         = row.get('faculty')
                    domain          = row.get('domain')
                    start_year      = row.get('start_year')
                    graduation_year = row.get('graduation_year')

                    # Skip if username is missing, as it's the key to finding the student
                    if not username:
                        print(f"Skipping row due to missing username: {row}")
                        continue

                    # Find the user and their student data
                    student_user = User.query.filter_by(username=username).first()
                    if not student_user:
                        print(f"User with username '{username}' not found. Skipping.")
                        continue

                    # Get or create the student data record
                    student_data = student_user.student_info
                    if not student_data:
                        student_data = Student(user_id=student_user.id)
                        db.session.add(student_data)

                    # Update the student data with values from the CSV, if they exist
                    if faculty:
                        student_data.faculty = faculty
                    if domain:
                        student_data.domain = domain

                    try:
                        if start_year:
                            student_data.start_year = int(start_year)
                        if graduation_year:
                            student_data.graduation_year = int(graduation_year)
                    except ValueError:
                        print(f"Invalid year data for user '{username}'. Skipping update for this row.")
                        continue

                    updated_count += 1

                db.session.commit()
                flash(f'{updated_count} student records were successfully updated from the CSV.', 'success')
                return redirect(url_for('employee_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during bulk student data update: {e}', 'error')
                return redirect(url_for('employee_dashboard'))

    employee = User.query.filter_by(username=current_user.username).first()
    all_students = employee.students_under_care.all()

    return render_template('employee_dashboard.html', now_user=current_user, students=all_students)

@app.route('/student-dashboard', methods=['GET', 'POST'])
@login_required
@student_required
def student_dashboard():
    if request.method == 'POST':
        if 'logout' in request.form:
            return redirect(url_for('logout'))

        if 'request_document' in request.form:
            # Get the document type
            doc_type = request.form.get('document-type')

            if doc_type == 'adeverinta_student':
                try:
                    # Get student data
                    student_name = current_user.username
                    faculty      = current_user.student_info.faculty
                    domain       = current_user.student_info.domain
                    start_year   = current_user.student_info.start_year
                    end_year     = current_user.student_info.graduation_year
                    reason       = request.form.get('reason')

                    # Hold the PDF data in a buffer
                    buffer = io.BytesIO()

                    # Create a document template
                    doc = SimpleDocTemplate(buffer, pagesize=A4)
                    styles = getSampleStyleSheet()
                    story = []

                    # Add the header as a Paragraph
                    title = Paragraph("ADEVERINTA DE STUDENT", styles['Heading1'])
                    story.append(title)
                    story.append(Spacer(1, 12)) # Adds a vertical space of 12 points

                    # Create the main body text using the Paragraph class
                    body_text_1 = f"Prezenta se elibereaza domnului/doamnei student(a) {student_name} la facultatea {faculty}, specializarea {domain}, promotie {start_year} - {end_year} pentru a-i servi la: {reason}."
                    body_text_2 = "Va multumim pentru intelegere!"

                    # Create Paragraphs for each line of text. The Paragraph class handles wrapping.
                    p1 = Paragraph(body_text_1, styles['Normal'])
                    story.append(p1)
                    story.append(Spacer(1, 12)) # Adds a vertical space

                    p2 = Paragraph(body_text_2, styles['Normal'])
                    story.append(p2)
                    story.append(Spacer(1, 12)) # Adds a vertical space

                    # Add other content as needed...

                    # Build the document
                    doc.build(story)

                    # Move the buffer's cursor to the beginning
                    buffer.seek(0)

                    # Create a new log entry
                    new_log = Log(
                        user_id=current_user.id,
                        document_type=doc_type, # You can get this from a form field if you have multiple document types
                        requested_at=datetime.utcnow(),
                        served_at=datetime.utcnow()
                    )

                    db.session.add(new_log)
                    db.session.commit()

                    # Serve the generated PDF to the user
                    return send_file(
                        buffer,
                        download_name='Adeverinta_Student.pdf',
                        as_attachment=True,
                        mimetype='application/pdf'
                    )
                except Exception as e:
                    flash(f"An error occurred: {str(e)}", 500)
                    return redirect(url_for('student_dashboard'))

            elif doc_type == 'situatie_scolara':
                # Create a new log entry
                new_log = Log(
                    user_id=current_user.id,
                    document_type=doc_type,
                    requested_at=datetime.utcnow(),
                    served_at=datetime.utcnow()
                )

                db.session.add(new_log)
                db.session.commit()
                return redirect(url_for('student_dashboard'))

            elif doc_type == 'foaie_matricola':
                # Create a new log entry
                new_log = Log(
                    user_id=current_user.id,
                    document_type=doc_type, # You can get this from a form field if you have multiple document types
                    requested_at=datetime.utcnow(),
                    served_at=datetime.utcnow()
                )

                db.session.add(new_log)
                db.session.commit()
                return redirect(url_for('student_dashboard'))

    recent_requests = Log.query.filter_by(user_id=current_user.id)\
                           .order_by(desc(Log.requested_at))\
                           .limit(5)\
                           .all()
    return render_template('student_dashboard.html', now_user=current_user, recent_requests=recent_requests)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials"

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
# Driver code
if __name__ in "__main__":
    with app.app_context():
        db.create_all()

        try:
            # Checking if the ADMIN role exists
            admin_role = Role.query.filter_by(name=RoleType.ADMIN.value).first()
            if not admin_role:
                admin_role = Role(name=RoleType.ADMIN.value)
                db.session.add(admin_role)
                db.session.commit()
                print("ADMIN role creted")
            else:
                print("ADMIN role already exists")

            # Checking if the admin user exists
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                new_admin = User(
                    username = 'admin',
                    password = '1234',
                    email    = 'admin@gmail.com',
                    role     = admin_role
                )
                db.session.add(new_admin)
                db.session.commit()
                print("Default admin user created")
            else:
                print("Default admin user already exists")

        except Exception as e:
            print(f"ERROR: {e}")

    app.run(debug=True)

