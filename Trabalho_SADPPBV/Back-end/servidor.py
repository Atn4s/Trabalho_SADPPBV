# ATENÇÃO JOÃO: FAZER LOGIN CADASTRO E LOGOFF!

import hashlib
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, current_user, jwt_required
import sqlite3
import Tables
import sys

app = Flask('SADPPBV')
app.config['JWT_SECRET_KEY'] = 'joao-super-secret'
jwt = JWTManager(app)

Tables.initialize_database()

def authenticate_user(registro, senha):
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, tipo_usuario FROM usuario WHERE registro = ?", (registro,))
    user = cursor.fetchone()
    conn.close()
    if user and user[1] == hashlib.sha512(senha.encode()).hexdigest():
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

@app.route('/usuarios', methods=['POST'])
@jwt_required()
def cadastrar_novo_usuario():
    if current_user['tipo_usuario'] != 1:
        return jsonify({"success": False, "message": "Apenas o usuário administrador pode cadastrar novos usuários"}), 403

    data = request.get_json()
    registro = data.get('registro')
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    tipo_usuario = data.get('tipo_usuario')

    if not registro or not nome or not email or not senha or tipo_usuario is None:
        return jsonify({"success": False, "message": "Dados incompletos. Certifique-se de fornecer todos os campos necessários."}), 400

    senha_hash = hashlib.sha512(senha.encode()).hexdigest()

    con = sqlite3.connect('project_data.db')
    cur = con.cursor()

    cur.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                (nome, registro, email, senha_hash, tipo_usuario))

    con.commit()
    con.close()

    return jsonify({"success": True, "message": "Usuário criado com sucesso"}), 200

# Rota para listar todos os usuários
@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    # Seu código para listar todos os usuários aqui
    return jsonify({"usuarios": [], "success": True, "message": "Lista de todos os usuários"}), 200

# Rota para obter um usuário específico
@app.route('/usuarios/<int:registro>', methods=['GET'])
def obter_usuario(registro):
    # Seu código para obter um usuário específico aqui
    return jsonify({"usuario": {}, "success": True, "message": "Lista de todos os usuários"}), 200

# Rota para atualizar um usuário
@app.route('/usuarios/<int:registro>', methods=['PUT'])
def atualizar_usuario(registro):
    # Seu código para atualizar um usuário aqui
    return jsonify({"success": True, "message": "Usuário atualizado com sucesso"}), 200

# Rota para excluir um usuário
@app.route('/usuarios/<int:registro>', methods=['DELETE'])
def excluir_usuario(registro):
    # Seu código para excluir um usuário aqui
    return jsonify({"success": True, "message": "Usuário excluído com sucesso"}), 200

# Rota para cadastrar ponto
@app.route('/pontos', methods=['POST'])
def cadastrar_ponto():
    # Seu código para cadastrar um ponto aqui
    return jsonify({"success": True, "message": "Ponto criado com sucesso"}), 200

# Rota para listar todos os pontos
@app.route('/pontos', methods=['GET'])
def listar_pontos():
    # Seu código para listar todos os pontos aqui
    return jsonify({"pontos": [], "success": True, "message": "Lista de todos os pontos"}), 200

# Rota para criar um novo segmento
@app.route('/segmentos', methods=['POST'])
def criar_segmento():
    # Seu código para criar um novo segmento aqui
    return jsonify({"success": True, "message": "Segmento criado com sucesso"}), 200

# Rota para listar todos os segmentos
@app.route('/segmentos', methods=['GET'])
def listar_segmentos():
    # Seu código para listar todos os segmentos aqui
    return jsonify({"segmentos": [], "success": True, "message": "Lista de todos os segmentos"}), 200

# Rota para atualizar um segmento
@app.route('/segmento/<int:id>', methods=['PUT'])
def atualizar_segmento(id):
    # Seu código para atualizar um segmento aqui
    return jsonify({"success": True, "message": "Segmento atualizado com sucesso"}), 200

# Rota para excluir um segmento
@app.route('/segmento/<int:id>', methods=['DELETE'])
def excluir_segmento(id):
    # Seu código para excluir um segmento aqui
    return jsonify({"success": True, "message": "Segmento removido com sucesso"}), 200

# Rota para calcular rota entre origem e destino
@app.route('/rotas', methods=['POST'])
def calcular_rota():
    # Seu código para calcular a rota entre origem e destino aqui
    return jsonify({"success": True, "message": "Rota calculada com sucesso"}), 200

# Rota para login no sistema
@app.route('/login', methods=['POST'])
def fazer_login():
    # Seu código para fazer login no sistema aqui
    return jsonify({"success": True, "message": "Login bem-sucedido"}), 200

# Rota para logout do sistema
@app.route('/logout', methods=['POST'])
def fazer_logout():
    # Seu código para fazer logout do sistema aqui
    return jsonify({"success": True, "message": "Logout bem-sucedido"}), 200


if __name__ == '__main__':
    # Escolha a porta para rodar!
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000  # porta padrão

    # Inicie o servidor Flask
    app.run(debug=True, port=port)
