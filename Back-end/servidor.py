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
import logging
import traceback

# Definir o nível de log para depuração
logging.basicConfig(level=logging.DEBUG)

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

#decodificar token

def decode_token(encoded_token, csrf_value, allow_expired=False):
    try:
        token_parts = encoded_token.split(".")
        if len(token_parts) != 3:
            raise jwt.exceptions.InvalidTokenError("Token inválido: formato incorreto")
        
        return jwt.decode(encoded_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"], options={"verify_signature": True})
    except jwt.ExpiredSignatureError:
        if allow_expired:
            return jwt.decode(encoded_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"], options={"verify_signature": False})
        raise
    except jwt.InvalidTokenError:
        logging.debug("Token inválido")
        raise

# Autenticação do usuário!                                                                              
def authenticate_user(registro, senha_hash_blake2b):
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, tipo_usuario FROM usuario WHERE registro = ?", (registro,))
    users = cursor.fetchall()

    for user in users:
        if user and user[1] == senha_hash_blake2b:
            return {'user_id': user[0], 'tipo_usuario': user[2], 'senha': senha_hash_blake2b}
    return None

def verify_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')
            if auth_header:
                token = auth_header.split(" ")[1]
                if token in revoked_tokens:
                    logging.debug("Token revogado")
                    return jsonify({'message': 'Não autenticado. Faça login novamente.', 'success': False}, 401)
                else:
                    logging.debug("Token válido")
                    return jwt_required()(f)(*args, **kwargs)  # Verifica se o token é válido
            else:
                logging.debug("Token de autenticação não encontrado")
                return jsonify({'message': 'Token de autenticação não encontrado', 'success': False}, 401)
        except Exception as e:
            logging.error(f"Erro: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}, 500)
    return decorated_function

# Login método POST
@app.route('/login', methods=['POST'])
def login():
    registro = request.json.get('registro', None)
    senha = request.json.get('senha', None)

    try:
        if not registro or not senha:
            logging.debug("Credenciais inválidas")
            return jsonify({"success": False, "message": "Credenciais inválidas"}), 401

        senha_hash_blake2b = hashlib.blake2b(senha.encode()).hexdigest()  # Criptografa a senha em MD5 novamente
        current_user = authenticate_user(registro, senha_hash_blake2b)
        if not current_user:
            return jsonify({"success": False, "message": "Credenciais inválidas"}), 401

        token = create_access_token(identity={'user_id': current_user['user_id'], 'tipo_usuario': current_user['tipo_usuario'], 'senha': senha_hash_blake2b, 'registro': registro}, expires_delta=ACCESS_EXPIRES)
        return jsonify({"success": True, "message": "Login bem-sucedido", "token": token}), 200

    except Exception as e:
            logging.error(f"Erro ao processar o login: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            return jsonify({"success": False, "message": "Erro ao processar a solicitação de login"}), 500

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
    except Exception as e:
        logging.error(f"Erro ao processar o logout: {e}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Erro ao processar a solicitação de logout"}), 500

# Usuários método POST
@app.route('/usuarios', methods=['POST'])
@verify_token
def cadastrar_usuario():
    current_user = get_jwt_identity()
    try:
        if current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 para administrador
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(" ")[1]  # Obtém o token do header de autorização
            
            new_user = request.json
            if not new_user:
                return jsonify({"success": False, "message": "Dados de usuário ausentes. Por favor, forneça os dados necessários."}), 400

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()
            try:
                senha_hash_blake2b = hashlib.blake2b(new_user['senha'].encode()).hexdigest()  # Criptografa a senha em MD5 novamente
                cursor.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                           (new_user['nome'], new_user['registro'], new_user['email'], senha_hash_blake2b, new_user['tipo_usuario']))
                conn.commit()
                return jsonify({"success": True, "message": "Novo usuário cadastrado com sucesso."}), 200
            except sqlite3.IntegrityError as e:
                return jsonify({"success": False, "message": "O registro já está em uso. Por favor, escolha um registro diferente."}), 400
        else:
            return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para realizar esta ação."}), 401
    except Exception as e:
        logging.error(f"Erro ao processar o cadastro do usuário: {e}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Erro ao processar a solicitação de cadastro de usuário"}), 500

@app.route('/usuarios', methods=['GET'])
@verify_token
def get_usuario():
    try:
        current_user = get_jwt_identity()
        if current_user:
            logging.debug("Usuário autenticado")
            if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 (administrador)
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario")
                data = cursor.fetchall()
                usuarios = [{'id': row[0], 'nome': row[1], 'registro': row[2], 'email': row[3], 'tipo_usuario': row[4]} for row in data]
                for usuario in usuarios:
                    usuario.pop('senha', None)  # Remove a senha, se existir
                conn.close()
                return jsonify({'usuarios': usuarios})
            else:  # Se o tipo de usuário não for 1 (administrador), retorna apenas a conta do próprio usuário
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario WHERE registro=?", (current_user['registro'],))
                data = cursor.fetchone()
                if data:
                    usuario = {'id': data[0], 'nome': data[1], 'registro': data[2], 'email': data[3], 'tipo_usuario': data[4]}
                    conn.close()
                    return jsonify({'usuario': usuario})
                else:
                    return jsonify({"success": False, "message": "O usuário não foi encontrado."}), 404
        else:
            logging.error('Não foi possível obter as informações do usuário')
            return jsonify({'message': 'Não foi possível obter as informações do usuário', 'success': False}), 401
    except Exception as e:
        logging.error(f'Erro ao processar a solicitação de obter usuário: {e}')
        logging.error(f'Traceback: {traceback.format_exc()}')
        return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}), 500


@app.route('/usuarios/<string:registro>', methods=['GET'])
@verify_token
def get_usuario_by_registro(registro):
    try:
        current_user = get_jwt_identity()
        if current_user:
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and current_user['registro'] == registro):  # Verifica se é um administrador ou se é um usuário comum acessando seus próprios dados
                logging.debug("Verificando permissões de acesso")
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
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 401
        else:
            logging.error('Acesso negado. Você não está autenticado.')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        logging.error(f'Erro ao processar a solicitação: {e}')
        logging.error(f'Traceback: {traceback.format_exc()}')
        return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}), 500


# Servidor Flask
if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000

    app.run(debug=True, port=port, host='0.0.0.0')
