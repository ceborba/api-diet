from flask_login import UserMixin
from datetime import datetime
from database import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='user')
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
    inside_diet = db.Column(db.Boolean, default=True)
    
    
