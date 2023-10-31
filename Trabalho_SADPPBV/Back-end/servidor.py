import hashlib
import sqlite3
import sys
import secrets
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from functools import wraps
import Tables

# Configurações do aplicativo Flask
app = Flask('SADPPBV')
CORS(app, resources={r"/*": {"origins": "*"}})  # Configuração mais explícita do CORS para permitir todas as origens

# Configurações JWT
key = secrets.token_hex(32)
app.config['JWT_SECRET_KEY'] = key
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
ACCESS_EXPIRES = timedelta(hours=1)
revoked_tokens = set()
jwt = JWTManager(app)

# Inicializar base de dados (Tables.py)
Tables.initialize_database()

# Autenticação do usuário!                                                                              
def authenticate_user(registro, senha):
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, tipo_usuario FROM usuario WHERE registro = ?", (registro,))
    users = cursor.fetchall()

    for user in users:
        if user and user[1] == senha:
            return {'user_id': user[0], 'tipo_usuario': user[2]}
    return None

# Verificação Token JWT
def verify_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')
            if auth_header:
                token = auth_header.split(" ")[1]
                if token in revoked_tokens:
                    return jsonify({'message': 'Não autenticado. Faça login novamente.', 'success': False}), 401
                else:
                    return jwt_required()(f)(*args, **kwargs)  # Verifica se o token é válido
            else:
                return jsonify({'message': 'Token de autenticação não encontrado', 'success': False}), 401
        except Exception as e:
            print(e)
            return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}), 500
    return decorated_function

# Login método POST
@app.route('/login', methods=['POST'])
def login():
    registro = request.json.get('registro', None)
    senha = request.json.get('senha', None)

    if not registro or not senha:
        return jsonify({"success": False, "message": "Credenciais inválidas"}), 401

    current_user = authenticate_user(registro, senha)
    if not current_user:
        return jsonify({"success": False, "message": "Credenciais inválidas"}), 401

    token = create_access_token(identity=current_user)
    return jsonify({"success": True, "message": "Login bem-sucedido", "token": token}), 200

# Logout método POST 
@app.route('/logout', methods=['POST'])
@verify_token
def fazer_logout():
    try:
        # Obtenha o token JWT da requisição
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]  # Obtém o token do header de autorização

        # Adicione o token à lista de tokens revogados
        revoked_tokens.add(token)

        return jsonify({"success": True, "message": "Logout bem-sucedido"}), 200
    except:
        return jsonify({"success": False, "message": "Não autenticado"}), 401

# Usuários método POST
@app.route('/usuarios', methods=['POST'])
@verify_token
def cadastrar_usuario():
    current_user = get_jwt_identity()
    if current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 para administrador
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]  # Obtém o token do header de autorização
        
        new_user = request.json
        if not new_user:
            return jsonify({"success": False, "message": "Dados de usuário ausentes. Por favor, forneça os dados necessários."}), 400

        conn = sqlite3.connect('project_data.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                           (new_user['nome'], new_user['registro'], new_user['email'], hashlib.md5(new_user['senha'].encode()).hexdigest(), new_user['tipo_usuario']))
            conn.commit()
            return jsonify({"success": True, "message": "Novo usuário cadastrado com sucesso."}), 200
        except sqlite3.IntegrityError as e:
            return jsonify({"success": False, "message": "O registro já está em uso. Por favor, escolha um registro diferente."}), 400
    else:
        return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para realizar esta ação."}), 401

# Usuários método GET
@app.route('/usuarios', methods=['GET'])
@verify_token
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

# Usuários método GET por ID
@app.route('/usuarios/<string:registro>', methods=['GET'])
@verify_token
def get_usuario_by_registro(registro):
    current_user = get_jwt_identity()
    if current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 para administrador
        conn = sqlite3.connect('project_data.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario WHERE registro=?", (registro,))
        data = cursor.fetchone()
        if data:
            usuario = {'id': data[0], 'nome': data[1], 'registro': data[2], 'email': data[3], 'tipo_usuario': data[4]}
            conn.close()
            return jsonify({'usuario': usuario})
        else:
            return jsonify({"success": False, "message": "O usuário com o registro especificado não foi encontrado."}), 404
    else:
        return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para realizar esta ação."}), 401

# Servidor Flask
if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000

    app.run(debug=True, port=port, host='0.0.0.0')
