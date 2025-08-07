# Imports
from flask            import Flask, render_template, session, redirect, url_for, request
from flask_scss       import Scss
from flask_sqlalchemy import SQLAlchemy
from flask_login      import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
from enum             import Enum

class RoleType(Enum):
    ADMIN    = 'ADMIN'
    EMPLOYEE = 'EMPLOYEE'
    STUDENT  = 'STUDENT'

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
        return f"<Role     {self.name}>"

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    role_id  = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__(self):
        return f"<User     '{self.username}'>"

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

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if current_user.is_authenticated and current_user.role.name == RoleType.ADMIN.value:
        return render_template('admin_dashboard.html')
    else:
        return 'You are not allowed here!'

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

