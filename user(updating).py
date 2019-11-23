import sys
import os;
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Blueprint
auth = Blueprint('auth', __name__)

from flask import render_template, redirect, request
from flask import url_for, flash
from flask_login import login_user, logout_user, login_required, LoginManager, login_manager

from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, IntegerField, validators
from wtforms import BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email


app = Flask(__name__)


appdir = os.path.abspath(os.path.dirname(__file__))
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.session_protection = 'strong'
login_manager.init_app(app)

app.config["SQLALCHEMY_DATABASE_URI"] = \
  f"sqlite:///{os.path.join(appdir, 'user.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']="ADFGAERTASDFAGT245242WEF"

db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

class User(db.Model):
  __tablename__ = "Users"
  user_id = db.Column(db.Integer(), primary_key=True)
  password = db.Column(db.String(64))
  email = db.Column(db.String(64), unique=True)
  # firstname = db.Column(db.Unicode(64), nullable=False)
  # lastname = db.Column(db.Unicode(64), nullable=False)
  # age = db.Column(db.Integer(), nullable=False)
  # phone = db.Column(db.Unicode(64), nullable=False)
  # country = db.Column(db.Unicode(64), nullable=False)
  # gender = db.Column(db.Unicode(64), nullable=False)
  # tokens = db.relationship("Tokens", backref="user_id")

  def is_active(self):
      return True

  def is_authenticated(self):
      return True

  def is_anonymous(self):
      return False

  def get_id(self):
      return self.user_id

  def set_password(self, password):
      self.password = generate_password_hash(password)

  def check_password(self, password):
      return check_password_hash(self.hashed_password, password)

def add_user (email, password):
  newuser = User(password=generate_password_hash(password, method='sha256'), email=email)
  db.session.add(newuser)
  db.session.commit()
  
  def find_user (target_user_id):
    result = User.query.filter_by(user_id = target_user_id)
    return result



@app.route("/")
def home():
  db.create_all()
  return render_template("index.html")
####################Modified Part#########################
class LoginForm(Form):
  email = StringField("email", [DataRequired(message="Please enter a valid email")])
  email_retype = StringField("repeat email", [DataRequired(message="Please enter a valid email"), EqualTo("email", message="Please enter a matched email")])
  password = PasswordField ("password", [DataRequired(message="Please enter your password")])
  password_retype = StringField("repeat password", [DataRequired(message="Please enter your password again"), EqualTo("password", message="Please enter a matched password")])
  
@app.route("/signup", methods=["GET","POST"])
def signup():
  form = LoginForm()
  if request.method == 'POST':
    #email = request.form['email']
    #password = request.form['password']
    email = form.email.data
    email_retype = form.email_retype.data
    password = form.password.data
    password_retype = form.password_retype.data
    add_user(email, password)
    return redirect(url_for("home"))
  return render_template("signup.html", form=form)
############################################################
  
@app.route("/login", methods=["GET","POST"])
def login():
  if request.method == 'POST':
    try:
      email = request.form['email']
      password = request.form['password']
      user = db.session.query(User).filter_by(email=email).first()
      if user is not None and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for("home"))
      return render_template("login.html")
    except:
      return render_template("login.html")
  else:
    return render_template("login.html")
  

@app.route("/logout")
@login_required
def logout():
  logout_user()
  return redirect(url_for("login"))

def verify_password(self, password):
  return check_password_hash(self.password, password)
