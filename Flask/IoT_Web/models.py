from datetime import datetime
from IoT_Web import db, login_manager #imports db = SQLAlchemy(app) from __init__.py file to create a db
from flask_login import UserMixin #UserMixin is a class that contains the following attributes IsAuthenticated, IsActive, IsAnonymous, GetId

@login_manager.user_loader
def load_user(user_id): #reloads the users from the user id stored in a session
    return User.query.get(int(user_id)) #returns the user for that id

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True) #id type integer, primary_key = unique id for users
    username = db.Column(db.String(20), unique=True, nullable=False) #username type string with max length of 20 characters, unique usernames, nullable = must have a username
    email = db.Column(db.String(120), unique=True, nullable=False) #email type strnng with max length of 120 characters, unique emails, must have an email
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg') #hash image files that are 20 characters long, dont have to be unique because users can have the same profile pics, default image for users
    password = db.Column(db.String(60), nullable=False) #hash password 60 chars in length

    def __repr__(self): #__repr__ method defines how the objects are printed out
        return f"User('{self.username}', '{self.email}', '{self.image_file}')" #order in which objects are printed out

