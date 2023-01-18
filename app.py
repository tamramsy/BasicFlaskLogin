from datetime import datetime
import re
from flask import Flask, request, render_template, url_for, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
 
# email validating regex
emailRegex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$' 
 
# create Flask app
app = Flask(__name__)
 
# configure it to work with existing MariaDB
app.config['SQLALCHEMY_DATABASE_URI'] =\
    'mysql://root:''@localhost:3306/rnls'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
 
# user_info table model-
class user_info(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False)
    email = db.Column(db.Text, nullable=False)
    hash = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime, server_default=func.now())
    last_login = db.Column(db.DateTime)
 
# import the table to add the user's information
from app import user_info
 
# secret key for user sessions
app.secret_key = "REDACTED"
 
# index page
@app.route('/', methods=["GET", "POST"])
def index():
    return render_template('index.html')
 
#login page
@app.route('/login', methods=["GET", "POST"])
def login():
 
    # retrieve info from login form
    if request.method == 'POST':
        loginUN = request.form["lUN"]
        loginPass = request.form["lPass"]
 
        # check if the username entered is registered in the database
        if user_info.query.filter_by(username=loginUN).first() != None:
 
            # grab the user's row from the database
            userEntry = user_info.query.filter_by(username=loginUN).first()
 
            # check if the password entered matches up to the hashed password in the database
            if check_password_hash(userEntry.hash, loginPass):
                print(f"Login of {loginUN} is valid!")
 
                # store login information on a cookie
                session['username'] = loginUN
                session['email'] = userEntry.email
                return redirect('/')
            else:
 
                # failed login
                print(f'Login of {loginUN} is invalid!')
                return redirect('/')
        else:
 
            # failed login
            print('User has not registered yet!')
            return redirect('/')
    return render_template('login.html')
 
# code to log user out
@app.route('/logout', methods=["GET", "POST"])
def logout():
    
    # check if user is logged in
    if session['username']:
 
        #log user out
        session.pop('username', default=None)
        session.pop('email', default=None)
    return redirect('/')
 
# recieve information from html form
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        textPassword = request.form["txtPswd"]
        textUsername = request.form["txtUN"]
        textEmail = request.form["txtEmail"]
 
        # check if email is valid
        if re.search(emailRegex, textEmail):
 
            # check if the username or email exists in the db yet
            if db.session.query(user_info).filter_by(username=textUsername).first() is None:
                if db.session.query(user_info).filter_by(email=textEmail).first() is None:
                    
                    # hash password
                    passwordHash = generate_password_hash(textPassword)
 
                    # commit info to db
                    regAcc = user_info(username=textUsername, email=textEmail, hash=passwordHash, creation_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    db.session.add(regAcc)
                    db.session.commit()
                else:
                    print('Email is taken!')
            else:
                print('Username is taken!')
        else:
            print('Invalid email!')
    return render_template('register.html')
 
# generic Flask app guard
if __name__ == '__main__':
    app.run()
