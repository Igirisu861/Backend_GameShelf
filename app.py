import datetime
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import mongo, init_db
from flask_bcrypt import Bcrypt
from config import Config
from bson.json_util import ObjectId
from steam_web_api import Steam

#inicialización de variables y app
app = Flask(__name__)
app.config.from_object(Config)
Bcrypt = Bcrypt(app)
jwt = JWTManager(app)

STEAM_KEY = Config.STEAM_KEY
steam = Steam(STEAM_KEY)
init_db(app)

#registro de usuarios
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

#login de usuarios 
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = mongo.db.users.find_one({"email":email})

    if user and Bcrypt.check_password_hash(user['password'], password):
        expiration = datetime.timedelta(days=365)
        access_token = create_access_token(identity=str(user["_id"]),expires_delta=expiration)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg":"Credenciales incorrectas"}), 401

#búsqueda de juegos   
@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    search_input = data.get('search_input')
    return steam.apps.search_games(search_input), 200
    
#creación de listas de usuarios
@app.route('/createlist', methods=['POST'])
@jwt_required()
def create_list():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    list_data = request.get_json()
    list_name = list_data.get('list_name')
    games = []

    result = mongo.db.lists.insert_one({'user_id':user_id, 'list_name':list_name, 'games':games})

    if result.acknowledged:
        return jsonify({'msg':'Lista creada con éxito!'}), 201
    else:
        return jsonify({'msg': 'Error al crear la lista'}), 400
    
#borrar listas
@app.route('/deletelist', methods=['DELETE'])
@jwt_required()
def delete_list():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    list_data = request.get_json()
    list_name = list_data.get('list_name')

    result = mongo.db.lists.find_one_and_delete({'user_id':user_id,'list_name':list_name})

    if result:
        return jsonify({'msg':'Lista eliminada correctamente'}), 201
    else:
        return jsonify({'msg': 'Error al eliminar la lista'}), 400

#cambiar el nombre de las listas  
@app.route('/changename', methods=['PUT'])
@jwt_required()
def update_list_name():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    list_data = request.get_json()
    list_name = list_data.get('list_name')
    new_name = list_data.get('new_name')

    result = mongo.db.lists.find_one_and_update(
        {'user_id':user_id, 'list_name':list_name}, 
        {'$set': {'list_name':new_name}}
        )

    if result:
        return jsonify({'msg':'Nombre actualizado'}), 201
    else:
        return jsonify({'msg': 'Error al actualizar el nombre'}), 400
    
#agregar juegos a la lista escogida
@app.route('/addgame', methods=['PUT'])
@jwt_required()
def add_game():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    data = request.get_json()
    game_name = data.get('game_name')
    list_name = data.get('list_name')

    search_results = steam.apps.search_games(game_name)
    if search_results and len(search_results['apps']) > 0:
        game = search_results['apps'][0]
        game_id = game['id']
        game_name = game['name']

        result = mongo.db.lists.find_one_and_update(
            {'user_id':user_id, 'list_name':list_name},
            {'$addToSet': {'games':{'game_id': game_id}}},
            return_document=True
        )
        if result:
            return jsonify({'msg':'Juego agregado con éxito!'}), 200
        else:
            return jsonify({'msg': 'Error al agregar juego'}), 400
    else:
        return jsonify({'msg':'El juego no se encontró en Steam'}), 404
    
#quitar juegos de la lista escogida
@app.route('/removegame', methods=['DELETE'])
@jwt_required()
def remove_game():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    data = request.get_json()
    game_id = data.get('game_id')
    list_name = data.get('list_name')

    result = mongo.db.lists.find_one_and_update(
        {'user_id': user_id, 'list_name': list_name},
        {'$pull': {'games': {'game_id': game_id}}},
        return_document=True
    )

    if result:
        return jsonify({'msg': 'Juego eliminado con éxito!'}), 200
    else:
        return jsonify({'msg': 'Error al eliminar el juego o lista no encontrada'}), 404

@app.route('/showlists', methods=['GET'])
@jwt_required()
def show_lists():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)

    user_lists = mongo.db.lists.find({'user_id':user_id})

    lists = []
    for user_list in user_lists:
        lists.append({
            'list_name': user_list['list_name'],
            'games': user_list.get('games', [])
        })
    
    return jsonify(lists), 200
    
#"nodemon" de flask
if __name__ == '__main__':
    app.run(debug=True)

