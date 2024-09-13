from datetime import datetime
from database import db

class Meal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    in_diet = db.Column(db.Boolean, default=True, nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)