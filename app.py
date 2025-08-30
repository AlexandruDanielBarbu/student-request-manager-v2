# Imports
import os
import csv
import io
import datetime

from dotenv           import load_dotenv
from google           import genai
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

# load the .env file
load_dotenv()

# Gemini AI setup
# Get the API key
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    print("You have to provide an API key for google Gemini.")

client = genai.Client(api_key=api_key)

# App
app = Flask(__name__)
Scss(app)

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Get the secret key for Flask login
secret_key = os.getenv("SESSION_SECRET_KEY")
# Set the secret key
app.config['SECRET_KEY'] = secret_key

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
        return f"<{self.id} - {self.username} - {self.email}>"

    def check_password(self, password):
        return self.password == password

class Student(db.Model):
    __tablename__ = 'students'

    id              = db.Column(db.Integer, primary_key=True)
    faculty         = db.Column(db.String(100), nullable=True)
    domain          = db.Column(db.String(100), nullable=True)
    start_year      = db.Column(db.Integer, nullable=True)
    graduation_year = db.Column(db.Integer, nullable=True)
    # full_name     = db.Column(db.String(100), nullable=True)

    user_id         = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_user_id'), unique=True, nullable=False)
    responsible_employee_id = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_students_responsible_employee'), nullable=True)

    def __repr__(self):
        return f"<Info {self.user.username}: {self.id} - {self.faculty} - {self.domain} - [{self.start_year}, {self.graduation_year}]>"

class Log(db.Model):
    __tablename__ = 'logs'

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    document_type = db.Column(db.String(100), nullable=False)
    requested_at  = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    served_at     = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)

    user          = db.relationship('User', backref='logs')

class Question(db.Model):
    __tablename__ = 'questions'

    id              = db.Column(db.Integer, primary_key=True)
    student_id      = db.Column(db.Integer, db.ForeignKey('students.id', name='fk_student_asking'), nullable=False)
    employee_id     = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_questions_employee_id'))
    question_text   = db.Column(db.Text, nullable=False)
    ai_answer       = db.Column(db.Text)
    employee_answer = db.Column(db.Text)
    asked_at        = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    answered_by_employee_at = db.Column(db.DateTime)

    student  = db.relationship('Student', backref='questions')
    employee = db.relationship('User', foreign_keys=[employee_id], backref='answered_questions')

    def __repr__(self):
        return f"<Question from {self.student.user.username} to {self.employee.username}>"

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


def check_if_valid_csv_file(file, redirect_to):
    if not file or not file.filename.endswith('.csv'):
        print('ERROR:    Please upload a valid CSV file for user creation.')
        return redirect(url_for(redirect_to))

def add_one_user(username, password, email, role):
    try:
        generic_role = Role.query.filter_by(name=role).first()

        # Checking if ROLE exists
        if not generic_role:
            generic_role = Role(name=role)

            db.session.add(generic_role)
            db.session.commit()

        user = User.query.filter((User.username == username) | (User.email == email)).first()

        # Checking if the user exists already
        if not user:
            user = User(
                username = username,
                password = password,
                email    = email,
                role     = generic_role
            )

            db.session.add(user)

            return True
        else:
            return False

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: {e}")
        return False

def delete_one_user(username):
    try:
        user_to_delete = User.query.filter_by(username=username).first()

        # Self deletion check
        if username == current_user.username:
            print('ERROR:    You cannot delete yourself!')
            return False

        # Non existent user deletion check
        if user_to_delete:
            db.session.delete(user_to_delete)
            return True
        else:
            print('WARNING:    This user does not exist therefore it cannot be deleted!')
            return False

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: {e}")
        return False

def asign_student_to_employee(student_name, employee_name):
    try:
        # Find the users
        student_user  = User.query.filter_by(username=student_name).first()
        employee_user = User.query.filter_by(username=employee_name).first()

        # Get the roles
        student_role = Role.query.filter_by(name='STUDENT').first()
        employee_role = Role.query.filter_by(name='EMPLOYEE').first()

        # Verify users
        if not student_user or student_user.role != student_role:
            print(f'ERROR:    User "{student_name}" not found or is not a student.')
            return False

        if not employee_user or employee_user.role != employee_role:
            flash(f'ERROR:    User "{employee_name}" not found or is not an employee.')
            return False

        # Get student specific data
        student_data = Student.query.filter_by(user=student_user).first()

        if not student_data:
            student_data = Student(user=student_user)
            db.session.add(student_data)

        student_data.responsible_employee = employee_user

        print(f"SUCCESS:    Asigned {student_name} to {employee_name}!")
        return True

    except Exception as e:
        db.session.rollback()
        print(f"ERROR:    {e}")
        return False

@app.route('/admin-dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    # We have some data from the forms to handle
    if request.method == 'POST':

        if 'add_user' in request.form:
            user_added = add_one_user(
                username = request.form.get('username'),
                password = request.form.get('password'),
                email = request.form.get('email'),
                role = request.form.get('role')
            )

            if user_added:
                db.session.commit()

            return redirect(url_for('admin_dashboard'))

        if 'delete_user' in request.form:
            user_deleted = delete_one_user(request.form.get('username'))

            if user_deleted:
                db.session.commit()

            return redirect(url_for('admin_dashboard'))

        if 'csv_add_user' in request.form:
            try:
                csv_file = request.files.get('csv_file')

                # If not then redirect back to admin_dashboard
                check_if_valid_csv_file(csv_file, 'admin_dashboard')

                # Work the .csv magic
                csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                csv_reader = csv.DictReader(csv_text, delimiter=',')
                created_count = 0

                for row in csv_reader:
                    username = row.get('username'),
                    email = row.get('email'),
                    password = row.get('password'),
                    role_name = row.get('role')

                    # Skip if any essential data is missing
                    if not all([username, email, password, role_name]):
                        print(f"Skipping row with missing data: {row}")
                        continue

                    user_added = add_one_user(
                        username = username[0],
                        password = password[0],
                        email = email[0],
                        role = role_name
                    )

                    if user_added:
                        created_count += 1

                db.session.commit()
                print(f"SUCCESS:    {created_count} users were successfully created from the CSV.")

                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                print(f"ERROR:    An error occurred during bulk user creation: {e}")

                return redirect(url_for('admin_dashboard'))

        if 'csv_delete_user' in  request.form:
            try:
                csv_file = request.files.get('csv_file')

                check_if_valid_csv_file(csv_file, 'admin_dashboard')

                # Work the .csv magic
                csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                csv_reader = csv.DictReader(csv_text, delimiter=',')
                deleted_count = 0

                for row in csv_reader:
                    user_deleted = delete_one_user(username=row.get('username'))

                    if user_deleted:
                        deleted_count += 1

                db.session.commit()
                print(f'SUCCESS:    {deleted_count} users were successfully deleted from the CSV.')
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                print(f'ERROR:    An error occurred during bulk user deletion: {e}')
                return redirect(url_for('admin_dashboard'))

        if 'logout' in request.form:
            return redirect(url_for('logout'))

        if 'join_students' in request.form:
            student_asigned = asign_student_to_employee(
                student_name = request.form.get('student_username'),
                employee_name = request.form.get('employee_username')
            )

            if student_asigned:
                db.session.commit()

            return redirect(url_for('admin_dashboard'))

        if 'csv_join_students' in request.form:
            try:
                csv_file = request.files.get('csv_file')

                check_if_valid_csv_file( csv_file, 'admin_dashboard' )

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

                    student_asigned = asign_student_to_employee(
                        student_name = student_username,
                        employee_name = employee_username
                    )

                    if student_asigned:
                        succes_count += 1

                db.session.commit()
                print(f'SUCCESS:    {succes_count} students were successfully asigned from the CSV.')
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                db.session.rollback()
                print(f'ERROR:    An error occurred during bulk user creation: {e}')
                return redirect(url_for('admin_dashboard'))

    # Render all users in a table
    all_users = User.query.all()

    return render_template(
        'admin_dashboard.html',
        users=all_users,
        now_user=current_user
    )

def update_one_student_info(student_username, faculty, domain, start_year, graduation_year):
    if not student_username:
        print('ERROR:    Provide student username')
        return False

    student_user = User.query.filter_by(username=student_username).first()
    if not student_user:
        print("ERROR:    The selected user does not exist!")
        return False

    student_data = student_user.student_info
    if not student_data:
        student_data = Student(user_id=student_user.id)
        db.session.add(student_data)
        db.session.commit()

    # Update user data here
    if faculty:
        student_data.faculty = faculty

    if domain:
        student_data.domain = domain

    try:
        if start_year:
            student_data.start_year = int(start_year)

        if graduation_year:
            student_data.graduation_year = int(graduation_year)

        return True
    except ValueError:
        print("ERROR:    Start year or graduation year must be a valid number.")
        return False

@app.route('/employee-dashboard', methods=['GET', 'POST'])
@login_required
@employee_required
def employee_dashboard():
    if request.method == 'POST':
        if 'logout' in request.form:
            return redirect(url_for('logout'))

        if 'update_student' in request.form:
            student_data_updated = update_one_student_info(
                student_username = request.form.get('username'),
                faculty          = request.form.get('faculty'),
                domain           = request.form.get('domain'),
                start_year       = request.form.get('start_year'),
                graduation_year  = request.form.get('graduation_year'),
            )

            if student_data_updated:
                try:
                    db.session.commit()
                    print(f"SUCCESS:   Student data has been updated successfully!")
                except Exception as e:
                    db.session.rollback()
                    print(f"ERROR:    An error occurred while updating student data: {e}")

            return redirect(url_for('employee_dashboard'))

        if 'update_student_csv' in request.form:
            try:
                csv_file = request.files.get('csv_file')

                check_if_valid_csv_file(csv_file, 'employee_dashboard')

                csv_text = StringIO(csv_file.stream.read().decode('utf-8'))
                csv_reader = csv.DictReader(csv_text, delimiter=',')
                updated_count = 0

                for row in csv_reader:
                    student_data_updated = update_one_student_info(
                        student_username = row.get('username'),
                        faculty          = row.get('faculty'),
                        domain           = row.get('domain'),
                        start_year       = row.get('start_year'),
                        graduation_year  = row.get('graduation_year')
                    )

                    if student_data_updated:
                        updated_count += 1

                db.session.commit()
                print(f'SUCCESS:    {updated_count} student records were successfully updated from the CSV.')
                return redirect(url_for('employee_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during bulk student data update: {e}', 'error')
                return redirect(url_for('employee_dashboard'))

        if 'submit_answer' in request.form:
            try:
                question_id = int(request.form.get('question_id'))
            except Exception as e:
                print(f'ERROR:    Invalid question ID')
                return redirect(url_for('employee_dashboard'))

            employee_answer = request.form.get('employee_answer')

            question = Question.query.filter_by(id=question_id).first()
            if not question:
                print(f'ERROR:    No matching question with id {question_id} was found.')
                return redirect(url_for('employee_dashboard'))

            question.employee_answer = employee_answer
            question.answered_by_employee_at = datetime.now(timezone.utc)

            db.session.add(question)
            db.session.commit()

            return redirect(url_for('employee_dashboard'))

    # Very likely I can use current_user.students_under_care.all() instead
    employee = User.query.filter_by(username=current_user.username).first()

    all_students = employee.students_under_care.all()

    student_questions = Question.query\
        .filter_by(employee_id=current_user.id)\
        .filter(Question.answered_by_employee_at.is_(None))\
        .all()

    all_logs = db.session.query(Log).join(
        User, Log.user_id == User.id
    ).join(
        Student, User.id == Student.user_id
    ).filter(
        Student.responsible_employee_id == current_user.id
    ).limit(10).all()

    return render_template(
        'employee_dashboard.html',
        now_user = current_user,
        students = all_students,
        student_questions = student_questions,
        all_logs = all_logs
    )

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
                    story.append(Spacer(1, 12)) # This adds a vertical space of 12 points

                    # Create the main body text using the Paragraph class
                    body_text_1 = f"Prezenta se elibereaza domnului/doamnei student(a) {student_name}" +\
                                f"la facultatea {faculty}, specializarea {domain}, " +\
                                f"promotie {start_year} - {end_year} pentru a-i servi la: {reason}."
                    body_text_2 = "Va multumim pentru intelegere!"

                    # Create Paragraphs for each line of text. The Paragraph class handles wrapping.
                    p1 = Paragraph(body_text_1, styles['Normal'])
                    story.append(p1)
                    story.append(Spacer(1, 12)) # Adds a vertical space

                    p2 = Paragraph(body_text_2, styles['Normal'])
                    story.append(p2)
                    story.append(Spacer(1, 12)) # Adds a vertical space

                    # Build the document
                    doc.build(story)

                    # Move the buffer's cursor to the beginning
                    buffer.seek(0)

                    # Create a new log entry
                    new_log = Log(
                        user_id=current_user.id,
                        document_type=doc_type,
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
                    print(f"ERROR:    An error occurred: {e}")
                    return redirect(url_for('student_dashboard'))

            elif doc_type == 'situatie_scolara':
                # Create a new log entry
                new_log = Log(
                    user_id=current_user.id,
                    document_type=doc_type,
                )

                db.session.add(new_log)
                db.session.commit()

                return redirect(url_for('student_dashboard'))
            elif doc_type == 'foaie_matricola':
                # Create a new log entry
                new_log = Log(
                    user_id=current_user.id,
                    document_type=doc_type,
                )

                db.session.add(new_log)
                db.session.commit()

                return redirect(url_for('student_dashboard'))

        if 'submit_question' in request.form:
            question_text = request.form.get('question')
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=f"{question_text}"
            )

            question_entry = Question(
                student_id      = current_user.student_info.id,
                employee_id     = current_user.student_info.responsible_employee_id,
                question_text   = question_text,
                ai_answer       = response.text
            )

            db.session.add(question_entry)
            db.session.commit()

            return redirect(url_for('student_dashboard'))

    all_questions = Question.query.filter_by(student_id = current_user.student_info.id)\
                            .order_by(desc(Question.asked_at))\
                            .all()

    recent_requests = Log.query.filter_by(user_id=current_user.id)\
                           .order_by(desc(Log.requested_at))\
                           .limit(5)\
                           .all()
    return render_template(
        'student_dashboard.html',
        now_user = current_user,
        recent_requests = recent_requests,
        student_asked_questions = all_questions
    )


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

