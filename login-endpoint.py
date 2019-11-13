from flask import render_template, redirect, request
from flask import url_for, flash
from flask_login import login_user, logout_user


@auth.route("/login", methods=["GET","POST"])
def login():
	email = request.form.get("email")
	password = request.form.get("password")

	user = User.query.filter_by(email=email).first()

	if not user and not user.verify_password(password):
		flash('Incorrect email or password')
		return redirect(url_for("login"))

	login_user(user)

	return redirect(url_for("main_page"))


@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect(url_for("login"))