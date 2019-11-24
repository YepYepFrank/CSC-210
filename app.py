from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
import os, json

app = Flask(__name__, static_url_path='/static')
appdir = os.path.abspath(os.path.dirname(__file__))
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config["SQLALCHEMY_DATABASE_URI"] = \
	f"sqlite:///{os.path.join(appdir, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'you-will-never-guess'

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	username = db.Column(db.String, nullable=False)
	email = db.Column(db.String, nullable=False)
	password = db.Column(db.String, nullable=False)
	profile = db.relationship('Profile', backref='user', uselist=False)

class Profile(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	first_name = db.Column(db.String, nullable=False)
	last_name = db.Column(db.String, nullable=False)
	dob = db.Column(db.String, nullable=False)
	picture = db.Column(db.String, nullable=False)
	instruments = db.Column(db.String, nullable=False)
	genre = db.Column(db.String, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

db.create_all()

@app.route('/')
def home():
	if current_user.is_authenticated:
		return redirect(url_for('browse'))

	return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('browse'))

	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']

		currUser = User.query.filter_by(username=username).first()

		if currUser is None or not check_password_hash(currUser.password, password):
			flash('Invalid username or password')
			return redirect(url_for('login'))

		login_user(currUser)
		return redirect(url_for('browse'))

	return render_template('login.html', title='Log In')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	if current_user.is_authenticated:
		return redirect(url_for('browse'))
		
	if request.method == 'POST':
		username = request.form['username']
		email = request.form['email']
		password = generate_password_hash(request.form['password'])

		checkUserID = User.query.filter_by(username=username).first()
		checkUserEmail = User.query.filter_by(email=email).first()
		if checkUserID is not None or checkUserEmail is not None:
			flash('The username or email is already in use.')
			return redirect(url_for('signup'))

		user = User(username=username, email=email, password=password)
		db.session.add(user)
		db.session.commit()

		currentUser = User.query.filter_by(username=username).first()
		uid = currentUser.id
		login(currentUser)
		return redirect(url_for('createProfile', uid=uid, title='Create Profile'))

	return render_template('signup.html', title='Sign Up')

@app.route('/signup/<int:uid>', methods=['GET', 'POST'])
def createProfile(uid):
	if request.method == 'POST':
		first_name = request.form['first_name']
		last_name = request.form['last_name']
		picture = request.form['picture']
		dob = request.form['month'] + " " + request.form['day'] + " " + request.form['year']
		instruments = request.form.getlist('instruments')
		instrumentString = ""

		for value in instruments:
			if value != instruments[len(instruments) - 1]:
				instrumentString = instrumentString + value + ", "
			else:
				instrumentString = instrumentString + value

		genres = request.form.getlist('genres')
		genreString = ""

		for value in genres:
			if value != genres[len(genres) - 1]:
				genreString = genreString + value + ", "
			else:
				genreString = genreString + value

		currentProfile = Profile(first_name=first_name, last_name=last_name, picture=picture, dob=dob, instruments=instrumentString, genre=genreString, user=User.query.filter_by(id=uid).first())
		db.session.add(currentProfile)
		db.session.commit()
		return redirect(url_for('browse'))
	return render_template('create_profile.html', uid=uid, title='Create Profile')

@app.route('/browse')
@login_required
def browse():
	return render_template('browse.html')

@app.route('/profile')
@login_required
def user():
	return render_template('profile.html', title='Profile')

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('home'))

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

if __name__ == "__main__":
	app.run(debug=True)