# Imports
from flask import Flask
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from enum import Enum

class RoleType(Enum):
    ADMIN    = 'ADMIN'
    EMPLOYEE = 'EMPLOYEE'
    STUDENT  = 'STUDENT'

# App
app = Flask(__name__)
Scss(app)

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)


# Tables
class Role(db.Model):
    __tablename__ = 'roles'

    id    = db.Column(db.Integer, primary_key=True)
    name  = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return f"<Role     {self.name}>"

class User(db.Model):
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

