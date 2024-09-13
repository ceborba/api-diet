from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\Carlos\\Desktop\\portfolio\\api-diet\\api-diet\\instance\\database.db'

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

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
  data = request.json
  user = User.query.get(id_user)

  if id_user != current_user.id and current_user.role == "user":
    return jsonify({"message": "Operation not permitted"}), 403

  if user and data.get("password"):
    hashed_password = bcrypt.hashpw(data.get("password").encode('utf-8'), bcrypt.gensalt())
    user.password = hashed_password
    db.session.commit()

    return jsonify({"message": f"User {id_user} updated successfully"})
  
  return jsonify({"message": "User not found"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"])
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

if __name__ == '__main__':
    app.run(debug=True)