from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from models import mongo, init_db
from flask_bcrypt import Bcrypt
from config import Config
from bson.json_util import ObjectId
from steam_web_api import Steam

app = Flask(__name__)
app.config.from_object(Config)
Bcrypt = Bcrypt(app)
jwt = JWTManager(app)

STEAM_KEY = Config.STEAM_KEY
steam = Steam(STEAM_KEY)
init_db(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({'email': email}):
        return jsonify({'msg': 'El usuario ya existe'}), 400
    
    hashed_password = Bcrypt.generate_password_hash(password).decode('utf-8')

    result = mongo.db.users.insert_one({'email':email, 'password': hashed_password})
    if result.acknowledged:
        return jsonify({'msg': 'Usuario creado correctamente'}), 201
    else:
        return jsonify({'msg':'Hubo un error, los datos no fueron registrados'}), 400
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = mongo.db.users.find_one({"email":email})

    if user and Bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg":"Credenciales incorrectas"}), 401
    
@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    search_input = data.get('search_input')
    return steam.apps.search_games(search_input), 200
    
@app.route('/createlist', methods=['POST'])
def create_list():
    data = request.get_json()

