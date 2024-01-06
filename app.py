from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from database import configure, db, User
from werkzeug.exceptions import BadRequest
from datetime import timedelta
from dotenv import load_dotenv
import bcrypt
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)
configure(app)
CORS(app)

with app.app_context():
    db.create_all()

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    response = jsonify({'error': 'Campos faltando na requisição'}), 400
    return response

@jwt.expired_token_loader
def expired_token_callback(*argv):
    return jsonify({'error': 'Token expirado'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(*argv):
    return jsonify({'error': 'Token invalido'}), 401

@jwt.unauthorized_loader
def unauthorized_loader_callback(*argv):
    return jsonify({'error': 'Token vazio'}), 401

@app.route('/users', methods=['POST']) # Register a new user
def create_user():
    username = request.json.get('user', {}).get('username')
    email = request.json.get('user', {}).get('email')
    password = request.json.get('user', {}).get('password')
    if username is None or email is None or password is None:
        raise BadRequest('texto')
    else:
        check_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if username == '' or password == '' or email == '':
            return jsonify({"error": "Campos necessários não preenchidos"}), 422
        elif check_user:
            return jsonify({"error": "Username ou email já estão em uso"}), 422
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            hashed_password = str(hashed_password)[2:-1]
            new_user = User(username=username, email=email,password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            access_token = create_access_token(identity=username,expires_delta=timedelta(days=1))
            return jsonify({"message": "Usuário criado com sucesso!","access_token": access_token}), 201

@app.route('/users/login', methods=['POST']) # Login for existing user
def login():
    username = request.json.get('user', {}).get('username')
    password = request.json.get('user', {}).get('password')
    user = User.query.filter_by(username=username).first()
    if user:
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            access_token = create_access_token(identity=username,expires_delta=timedelta(days=1))
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"error": "Senha incorreta!"}), 401
    else:
        return jsonify({"error": "Usuário inexistente!"}), 422

@app.route('/user', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)