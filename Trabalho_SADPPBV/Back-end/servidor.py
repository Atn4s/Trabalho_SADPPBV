# CUIDADO COM CORSE! VERIFICAR RETORNOS 

from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity 
from datetime import timedelta
import hashlib
import sqlite3
import sys
import secrets
import Tables
from flask_cors import CORS
from functools import wraps

key = secrets.token_hex(32)
app = Flask('SADPPBV')
CORS(app)  # Isso habilitará CORS para todas as rotas
app.config['JWT_SECRET_KEY'] = key
jwt = JWTManager(app)

app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
ACCESS_EXPIRES = timedelta(hours=1)
revoked_tokens = set()

Tables.initialize_database()

#     _         _             _   _                           
#    / \  _   _| |_ ___ _ __ | |_(_) ___ __ _  ___ __ _  ___  
#   / _ \| | | | __/ _ \ '_ \| __| |/ __/ _` |/ __/ _` |/ _ \ 
#  / ___ \ |_| | ||  __/ | | | |_| | (_| (_| | (_| (_| | (_) |
# /_/   \_\__,_|\__\___|_| |_|\__|_|\___\__,_|\___\__,_|\___/ 
#                                                            
                              
def authenticate_user(registro, senha):
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, tipo_usuario FROM usuario WHERE registro = ?", (registro,))
    users = cursor.fetchall()

    for user in users:
        if user and user[1] == hashlib.md5(senha.encode()).hexdigest():
            return {'user_id': user[0], 'tipo_usuario': user[2]}
    return None

def jwt_required_with_token_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')
            if auth_header:
                access_token = auth_header.split(" ")[1]
                if access_token in revoked_tokens:
                    return jsonify({'message': 'Não autenticado. Faça login novamente.', 'success': False}), 401
            return f(*args, **kwargs)
        except Exception as e:
            print(e)
            return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}), 500
    return decorated_function

#  _                _       
# | |    ___   __ _(_)_ __  
# | |   / _ \ / _` | | '_ \ 
# | |__| (_) | (_| | | | | |
# |_____\___/ \__, |_|_| |_|
#             |___/   
#

@app.route('/login', methods=['POST'])
def login():
    registro = request.json.get('registro', None)
    senha = request.json.get('senha', None)

    if not registro or not senha:
        return jsonify({"success": False, "message": "Credenciais inválidas"}), 401

    current_user = authenticate_user(registro, senha)
    if not current_user:
        return jsonify({"success": False, "message": "Credenciais inválidas"}), 401

    access_token = create_access_token(identity=current_user)
    return jsonify({"success": True, "message": "Login bem-sucedido", "access_token": access_token}), 200

#  _                            _   
# | |    ___   __ _  ___  _   _| |_ 
# | |   / _ \ / _` |/ _ \| | | | __|
# | |__| (_) | (_| | (_) | |_| | |_ 
# |_____\___/ \__, |\___/ \__,_|\__|
#             |___/  

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in revoked_tokens


@app.route('/logout', methods=['POST'])
@jwt_required()
@jwt_required_with_token_check
def fazer_logout():
    try:
        # Obtenha o token JWT da requisição
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(" ")[1]  # Obtém o token do header de autorização

        # Adicione o token à lista de tokens revogados
        revoked_tokens.add(access_token)

        return jsonify({"success": True, "message": "Logout bem-sucedido"}), 200
    except:
        return jsonify({"success": False, "message": "Não autenticado"}), 401


#                              _           
#   _   _ ___ _   _  __ _ _ __(_) ___  ___ 
#  | | | / __| | | |/ _` | '__| |/ _ \/ __|
#  | |_| \__ \ |_| | (_| | |  | | (_) \__ \
#   \__,_|___/\__,_|\__,_|_|  |_|\___/|___/
#                    

@app.route('/usuarios', methods=['POST'])
@jwt_required()
@jwt_required_with_token_check
def cadastrar_usuario():
    current_user = get_jwt_identity()
    if current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 para administrador
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(" ")[1]  # Obtém o token do header de autorização
        
        new_user = request.json
        if not new_user:
            return jsonify({"success": False, "message": "Dados de usuário ausentes. Por favor, forneça os dados necessários."}), 400

        conn = sqlite3.connect('project_data.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                       (new_user['nome'], new_user['registro'], new_user['email'], hashlib.md5(new_user['senha'].encode()).hexdigest(), new_user['tipo_usuario']))
        conn.commit()

        return jsonify({"success": True, "message": "Novo usuário cadastrado com sucesso."}), 200
    else:
        return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para realizar esta ação."}), 401


@app.route('/usuarios', methods=['GET'])
@jwt_required()
@jwt_required_with_token_check
def get_usuario():
    current_user = get_jwt_identity()
    if current_user:
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1:
            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()
            cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario")
            data = cursor.fetchall()
            usuarios = [{'id': row[0], 'nome': row[1], 'registro': row[2], 'email': row[3], 'tipo_usuario': row[4]} for row in data]
            for usuario in usuarios:
                usuario.pop('senha', None)  # Remove a senha, se existir
            conn.close()
            return jsonify({'usuarios': usuarios})
        elif 'user_id' in current_user:
            user_id = current_user['user_id']
            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()
            cursor.execute("SELECT nome, registro, email FROM usuario WHERE id=?", (user_id,))
            data = cursor.fetchone()
            usuario = {'nome': data[0], 'registro': data[1], 'email': data[2]}
            conn.close()
            return jsonify({'usuario': usuario})
        else:
            return jsonify({'message': 'Chave "registro" não encontrada no objeto current_user', 'success': False}), 400
    else:
        return jsonify({'message': 'Não foi possível obter as informações do usuário', 'success': False}), 401



if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000

    app.run(debug=True, port=port, host='0.0.0.0')
