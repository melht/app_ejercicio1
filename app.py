### Backend usando Pyhton Flask y MongoDB con JWT y Bcrypt ###
### Universidad Anahuac Mayab
### 31-08-2024, Fabricio Suárez
### Prog de Dispositivos Móviles


#importamos todo lo necesario para que funcione el backend
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt

from models import mongo, init_db
from config import Config

#Inicializamos la aplicación y usamos el config file
app = Flask(__name__)
app.config.from_object(Config)

#Inicializamos a bcrypt y jwt
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

#Inicializamos el acceso a MongoDB
init_db(app)

#Definimos el endpoint para registrar un usuario
#Utilizamos el decorador @app.route('/') para definir la ruta de la URL e inmediatamente después
#la función que se ejecutará en esa ruta
@app.route('/register', methods=['POST'])
def register():
    #Estos son los datos que pasamos al post en formato JSON
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "Ese usuario ya existe"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # mongo.db.users.insert_one devuelve un objeto con dos propiedades "acknowledged" 
    # si se guardo correctamente y el id del documento insertado
    result = mongo.db.users.insert_one({"username":username,"email":email,"password": hashed_password})
    if result.acknowledged:
        return jsonify({"msg": "Usuario Creado Correctamente"}), 201
    else:
        return jsonify({"msg": "Hubo un error, no se pudieron guardar los datos"}),400

#Definimos la ruta del endpoint para el login
@app.route('/login', methods=['POST'])
def login():
    #Datos que traemos del formato json
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # users: coleccion
    user = mongo.db.users.find_one({"email": email})
    
    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Credenciales incorrectas"}), 401
    
#Creamos el endpoint protegido
@app.route('/data', methods=['POST'])
@jwt_required() #Solo con el decorador la función ya está protegida
def data():
    data = request.get_json()
    username = data.get('username')
    
    user = mongo.db.users.find_one({'username': username}, {'password': 0})
    
    if user:
        user["_id"]= str(user["_id"])
        return jsonify({'msg': 'Usuario encontrado', 'User:': user}), 200
    else:
        return jsonify({'msg': 'Usuario no encontrado'}), 404 
        
    

# En Python, cada archivo tiene una variable especial llamada __name__.
# Si el archivo se está ejecutando directamente (no importado como un módulo en otro archivo), 
# __name__ se establece en '__main__'.
# Esta condición verifica si el archivo actual es el archivo principal que se está ejecutando. 
# Si es así, ejecuta el bloque de código dentro de la condición.
# app.run() inicia el servidor web de Flask.
# El argumento debug=True  inicia el servidor web de desarrollo de Flask con el modo de 
# depuración activado, # lo que permite ver errores detallados y reiniciar automáticamente
# el servidor cuando se realizan cambios en el código. (SERIA COMO EL NODEMON)
if __name__ == '__main__':
    app.run(debug=True)