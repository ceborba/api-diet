from flask import Flask, request, jsonify
from models.user import User
from models.meal import Meal
from database import db
from datetime import datetime
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ceborba:admin123@localhost:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            login_user(user)
            return jsonify({"message": "Logged in successfully"})
        
        return jsonify({"message": "Invalid credentials"}), 400


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"})

@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")

    if username and password and name:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, name=name, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created successfully"})
    
    return jsonify({"message": "Invalid data"}), 400

@app.route("/admin/create_user", methods=["POST"])
@login_required
def create_admin_user():
    if current_user.role != 'admin':
       return jsonify({"message": "Operation not permitted"}), 403
    
    data = request.json
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")

    if username and password and name:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, name=name, role='admin')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Admin user created successfully"})
    
    return jsonify({"message": "Invalid data"}), 400


@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"username": user.username}
    
    return jsonify({"message": "User not found"}), 404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
  data = request.json
  user = User.query.get(id_user)

  if id_user != current_user.id and current_user.role != "admin":
    return jsonify({"message": "Operation not permitted"}), 403

  if user and data.get("password"):
    hashed_password = bcrypt.hashpw(data.get("password").encode('utf-8'), bcrypt.gensalt())
    user.password = hashed_password
    db.session.commit()

    return jsonify({"message": f"User {id_user} updated successfully"})
  
  return jsonify({"message": "User not found"}), 404

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
  user = User.query.get(id_user)

  if current_user.role != 'admin':
    return jsonify({"message": "Operation not permitted"}), 403

  if id_user == current_user.id:
    return jsonify({"message": "Deletion not allowed"}), 403

  if user:
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": f"User {id_user} deleted successfully"})
  
  return jsonify({"message": "User not found"}), 404

@app.route("/meals", methods=["POST"])
@login_required
def create_meal():
    data = request.json
    name = data.get("name")
    description = data.get("description")
    date_time = data.get("date_time")
    in_diet = data.get("in_diet")

    if date_time:
        try:
            date_time = datetime.fromisoformat(date_time)
        except ValueError:
            return jsonify({"message": "Invalid date_time format"}), 400
    else:
        date_time = datetime.utcnow()

    if name and isinstance(in_diet, bool):
        meal = Meal(
            name=name,
            description=description,
            date_time=date_time,
            in_diet=in_diet,
            user_id=current_user.id
        )
        db.session.add(meal)
        db.session.commit()
        return jsonify({"message": "Meal created successfully", "meal": meal.id})

    return jsonify({"message": "Invalid data"}), 400

@app.route("/meals/<int:id>", methods=["PUT"])
@login_required
def update_meal(id):
    data = request.json
    meal = Meal.query.get(id)

    if not meal:
        return jsonify({"message": "Meal not found"}), 404

    name = data.get("name")
    description = data.get("description")
    date_time = data.get("date_time")
    in_diet = data.get("in_diet")

    if name:
        meal.name = name

    if description:
        meal.description = description

    if date_time:
        try:
            meal.date_time = datetime.fromisoformat(date_time)
        except ValueError:
            return jsonify({"message": "Invalid date_time format"}), 400

    if isinstance(in_diet, bool):
        meal.in_diet = in_diet

    db.session.commit()
    return jsonify({"message": f"Meal updated successfully", "meal": meal.id})

@app.route("/meals/<int:id>", methods=["DELETE"])
@login_required
def delete_meal(id):
    meal = Meal.query.get(id)

    if meal.user_id != current_user.id:
        return jsonify({"message": "You don't have permission to delete this meal"}), 403
    
    if meal:
        db.session.delete(meal)
        db.session.commit()
        return jsonify({"message": "Meal deleted successfully"})
    
    return jsonify({"message": "Meal not found"}), 404

@app.route("/meals", methods=["GET"])
@login_required
def list_meals():
    meals = Meal.query.filter_by(user_id=current_user.id).all()

    if not meals:
        return jsonify({"message": "No meals found"}), 404
    
    meals_list = [
        {
            "id": meal.id,
            "name": meal.name,
            "description": meal.description,
            "date_time": meal.date_time.isoformat() if meal.date_time else None,
            "in_diet": meal.in_diet
        }
        for meal in meals
    ]

    return jsonify({"meals": meals_list})
  
@app.route("/meals/<int:id>", methods=["GET"])
@login_required
def get_meal(id):
    meal = Meal.query.get(id)

    if not meal:
        return ({"message": "Meal not found"}), 404
    
    if meal.user_id != current_user.id:
        return jsonify({"message": "You don't have permission to view this meal"}), 403
    
    meal_data = {
        "id": meal.id,
        "name": meal.name,
        "description": meal.description,
        "date_time": meal.date_time,
        "in_diet": meal.in_diet
    }

    return jsonify({"message": meal_data})


if __name__ == '__main__':
    app.run(debug=True)