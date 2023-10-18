from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity 
from datetime import timedelta
import hashlib
import sqlite3
import sys
import secrets
import Tables


key = secrets.token_hex(32)
app = Flask('SADPPBV')
app.config['JWT_SECRET_KEY'] = key
jwt = JWTManager(app)

app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
ACCESS_EXPIRES = timedelta(hours=1)
revoked_tokens = set()

Tables.initialize_database()

def authenticate_user(registro, senha):
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, tipo_usuario FROM usuario WHERE registro = ?", (registro,))
    users = cursor.fetchall()

    for user in users:
        if user and user[1] == hashlib.md5(senha.encode()).hexdigest():
            return {'user_id': user[0], 'tipo_usuario': user[2]}
    return None

@app.route('/login', methods=['POST'])
def login():
    registro = request.json.get('registro', None)
    senha = request.json.get('senha', None)

    if not registro or not senha:
        return jsonify({"message": "Usuário ou senha incorretos"}), 401

    current_user = authenticate_user(registro, senha)
    if not current_user:
        return jsonify({"message": "Usuário não encontrado"}), 401

    access_token = create_access_token(identity=current_user)
    return jsonify(access_token=access_token), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def fazer_logout():
    # Obtenha o token JWT da requisição
    auth_header = request.headers.get('Authorization')
    access_token = auth_header.split(" ")[1]  # Obtém o token do header de autorização

    # Adicione o token à lista de tokens revogados
    revoked_tokens.add(access_token)

    return jsonify({"success": True, "message": "Logout bem-sucedido"}), 200

@app.route('/usuario', methods=['POST'])
@jwt_required()
def cadastrar_usuario():
    current_user = get_jwt_identity()
    if current_user['tipo_usuario'] != 1:  # Verifica se o tipo de usuário é 1 para administrador
        return jsonify({"message": "Acesso negado. Você não tem permissão para realizar esta ação."}), 401

    new_user = request.json.get('novo_usuario', None)
    if not new_user:
        return jsonify({"message": "Dados de usuário ausentes. Por favor, forneça os dados necessários."}), 400

    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                   (new_user['nome'], new_user['registro'], new_user['email'], hashlib.md5(new_user['senha'].encode()).hexdigest(), new_user['tipo_usuario']))
    conn.commit()

    return jsonify({"message": "Novo usuário cadastrado com sucesso."}), 200


if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000

    app.run(debug=True, port=port)