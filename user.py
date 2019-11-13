import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from flask import render_template, redirect, request
from flask import url_for, flash
from flask_login import login_user, logout_user, login_required

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms import BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = \
  f"sqlite:///{os.path.join(appdir, 'user.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
	__tablename__ = "Users"
	user_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
  password = db.Column(db.Unicode(64), nullable=False)
  email = db.Column(db.Unicode(64), nullable=False)
  firstname = db.Column(db.Unicode(64), nullable=False)
  lastname = db.Column(db.Unicode(64), nullable=False)
  age = db.Column(db.Integer(), nullable=False)
  phone = db.Column(db.Unicode(64), nullable=False)
  country = db.Column(db.Unicode(64), nullable=False)
	gender = db.Column(db.Unicode(64), nullable=False)
  tokens = db.relationship("Tokens", backref="user_id")

def add_user (password, email, firstname, lastname, age, phone, ccountry, gender):
	newuser = User(password=password, email=email, firstname=firstname, lastname=lastname, age=age, phone=phone,country=country, gender=gender)
	db.session.add(newuser)
	db.session.commit()


class LoginForm(FlaskForm):
  email = StringField("Email", validators=[DataRequired(), Length(1,64), Email()])
  password = PasswordField("Password", validators=[DataRequired()])
  remember_me = BooleanField("Keep me logged in")
  submit = SubmitField("Log In")


@auth.route("/login", methods=["GET","POST"])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(email=form.email.data).first()
    if user is not None and \
      user.verify_password(form.password.data):
      login_user(user, form.remember_me.data)
      return redirect(url_for("main_page"))
    flash("Invalid Username or password.")
  return render_template("login.html", form=form)
  

@app.route("/logout")
@login_required
def logout():
  logout_user()
  return redirect(url_for("login"))

