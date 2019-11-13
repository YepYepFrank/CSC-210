import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from datetime import datetime

app = Flask(__name__)
##change this route to the dirction where the .db file is in
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///C:\\temp\\210project\\src\\test.db'
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
