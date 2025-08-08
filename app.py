# Imports
import os
import csv

from io               import StringIO
from flask            import Flask, render_template, session, redirect, url_for, request, flash
from flask_scss       import Scss
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc   import IntegrityError
from flask_login      import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
from enum             import Enum
from functools        import wraps

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

# App
app = Flask(__name__)
Scss(app)

# Database setup
app.config['SECRET_KEY'] = 'something'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)

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
    role_id  = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__(self):
        return f"<{self.username}>"

    def check_password(self, password):
        return self.password == password

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

    # Render all users in a table
    all_users = User.query.all()
    return render_template('admin_dashboard.html', users=all_users)

@app.route('/employee-dashboard')
@login_required
def employee_dashboard():
    if current_user.is_authenticated and current_user.role.name == RoleType.EMPLOYEE.value:
        return render_template('employee_dashboard.html')
    else:
        return 'You are not allowed here!'

@app.route('/student-dashboard')
@login_required
def student_dashboard():
    if current_user.is_authenticated and current_user.role.name == RoleType.STUDENT.value:
        return render_template('student_dashboard.html')
    else:
        return 'You are not allowed here!'


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

