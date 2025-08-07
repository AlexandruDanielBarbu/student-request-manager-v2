from flask import Flask
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy

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

    app.run(debug=True)

