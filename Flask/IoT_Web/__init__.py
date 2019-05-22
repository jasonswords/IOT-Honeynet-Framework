from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__) #specifies that this is the current file and will be represented as a web application
app.config['SECRET_KEY'] = '3c2eab0b2ecdd09ea4c573165565c5fb' #generated using secrets.token_hex(16) command from python console, used to protect cookies from XSS Forgery attacks
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' #setting db location, /// = relative path from the current file
db = SQLAlchemy(app) #creating db
bcrypt = Bcrypt(app) #hashing user passwords
login_manager = LoginManager(app) #handles sessions
login_manager.login_view = 'login' #when trying to access a page that requires you to be logged in, the user will be redirected to the login page
login_manager.login_message_category = 'info' #info is a bootstrap class which displays an alert

from IoT_Web import routes #need to import after app variable, else run into circular imports error (two or more modules depend on each other)
