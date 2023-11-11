import hashlib, sqlite3, sys, secrets, logging, traceback, re
from datetime import timedelta, datetime 
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity 
from flask_cors import CORS
from functools import wraps
import Tables

logging.basicConfig(level=logging.DEBUG) 
app = Flask('SADPPBV') 
CORS(app, resources={r"/*": {"origins": "*"}})  

key = secrets.token_hex(32)
csrf_value = secrets.token_hex(32)

app.config['JWT_SECRET_KEY'] = key
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
ACCESS_EXPIRES = timedelta(hours=1)
revoked_tokens = set()
jwt = JWTManager(app)

Tables.initialize_database()

def decode_token(encoded_token, csrf_value, allow_expired=False): # decodificação do token JWT!
    try:
        if encoded_token is None:
            raise jwt.exceptions.InvalidTokenError("Token não encontrado")    
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

def authenticate_user(registro, senha_hash_blake2b): # Autenticação do usuário, busca no banco de dados e retornas as informações para criar o token
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, tipo_usuario FROM usuario WHERE registro = ?", (registro,))
    users = cursor.fetchall()

    for user in users:
        if user and user[1] == senha_hash_blake2b:
            return {'user_id': user[0], 'tipo_usuario': user[2], 'senha': senha_hash_blake2b}
    return None

def verify_token(f): # verificação do token a cada operação
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization') # puxa o token do header para verificação 
            if auth_header:
                token = auth_header.split(" ")[1]
                if token in revoked_tokens:
                    logging.debug("[ Token revogado ]")
                    return jsonify({'message': 'Não autenticado. Faça login novamente.', 'success': False}, 401)    # 401 NÃO AUTENTICADO!
                else:
                    logging.debug("[ Token válido ]")
                    return jwt_required()(f)(*args, **kwargs)  # Token é válido = 200 lá em baixo!
            else:
                logging.debug("[ Token de autenticação não encontrado ]")
                return jsonify({'message': 'Token de autenticação não encontrado', 'success': False}, 401)  # 401 SEM TOKEN LOGO = NÃO AUTENTICADO!
        except Exception as e:
            logging.error(f"Erro: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}, 400)  
    return decorated_function

def get_user_info(current_user):
    info_keys = ['user_id', 'tipo_usuario', 'senha', 'registro']
    user_info = {key: current_user.get(key, 'não informado') for key in info_keys}
    return user_info

def code_response(logger, message, status_code):
    logger(message)
    return jsonify({"success": True, "message": message}), status_code

def handle_exceptions(logger, e):
    logger(f"Erro: {e}")
    logger(f"Traceback: {traceback.format_exc()}")
    return jsonify({"success": False, "message": "Erro ao processar a solicitação"}), 400


@app.route('/login', methods=['POST']) # Login método POST
def login():
    teste = request.get_json()
    logging.debug(f"Recebido pedido de login: {teste}")
    registro = request.json.get('registro', None)
    senha = request.json.get('senha', None)

    try:
        if not registro or not senha:
            logging.debug("[ Credenciais inválidas, verifique suas informações ]")
            
            return jsonify({"success": False, "message": "Credenciais inválidas"}), 401 # Não autenticado!

        senha_hash_blake2b = hashlib.blake2b(senha.encode()).hexdigest()  # Criptografa a senha em BLAKE2B 
        current_user = authenticate_user(registro, senha_hash_blake2b) # manda registro e senha para a função de autenticação do usuário
        if not current_user:
            logging.debug("[ Credenciais inválidas! Não está logado! ]")
            return jsonify({"success": False, "message": "Credenciais inválidas"}), 401 # Não autenticado!

        token = create_access_token(
            identity={
                'user_id': current_user['user_id'], 
                'tipo_usuario': current_user['tipo_usuario'], 
                'senha': senha_hash_blake2b, 
                'registro': registro
            }, 
            expires_delta=ACCESS_EXPIRES
        )
        logging.debug("[ Login Autorizado! ]")
        user_info = get_user_info(current_user)
        logging.debug(f"Dados do Login: {user_info}")
        return jsonify({"success": True, "message": "Login bem-sucedido", "token": token, "registro": registro}), 200 # Token e pode usar meu sistema!

    except Exception as e:
        return handle_exceptions(logging.error, e)
    
# Logout método POST 
@app.route('/logout', methods=['POST'])
@jwt_required()
@verify_token
def fazer_logout():
    try:
        auth_header = request.headers.get('Authorization') # Obtenha o token JWT do header
        token = auth_header.split(" ")[1]  
        current_user = get_jwt_identity()
        user_info = get_user_info(current_user)
        logging.debug(f"Recebido pedido de logout de: {user_info}")

        revoked_tokens.add(token) # Adicione o token à lista de tokens revogados logo não será possível reutiliza-lo!
        logging.debug("[ Logout Realizado com sucesso! ]")
        return code_response(logging.debug,"Logout bem-sucedido!",200)
        #return jsonify({"success": True, "message": "Logout bem-sucedido"}), 200 # tudo certo logout com sucesso!
    except Exception as e:
        logging.error(f"Erro ao processar o logout: {e}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Erro ao processar a solicitação de logout"}), 400 

@app.route('/usuarios', methods=['POST'])
@jwt_required()
@verify_token
def cadastrar_usuario():
    current_user = get_jwt_identity()
    try:
        if current_user and current_user['tipo_usuario'] == 1:          
            user_info = get_user_info(current_user)
            logging.debug(f"Recebido pedido de cadastrar usuário de: {user_info}")
            
            new_user = request.json
            if not new_user:
                logging.debug("[ Dados de usuário ausentes para cadastrar ]")
                return jsonify({"success": False, "message": "Dados de usuário ausentes. Por favor, forneça os dados necessários."}), 400 
            
            if not re.match(r'^\d+$', str(new_user.get('registro'))) and not re.match(r'^"\d+"$', str(new_user.get('registro'))):
                logging.debug("[ O campo registro deve conter apenas números ]")
                return jsonify({
                    "success": False,
                    "message": "O campo registro deve conter apenas números. Por favor, insira um valor numérico."
                }), 400

            required_fields = ['nome', 'registro', 'email', 'senha', 'tipo_usuario']

            if any(new_user.get(field) in (None, '') for field in required_fields):
                logging.debug("[ Dados de usuário ausentes ou em branco para cadastrar ]")
                return jsonify({"success": False, "message": "Dados de usuário ausentes ou em branco. Por favor, forneça os dados necessários."}), 400            
            elif new_user['tipo_usuario'] not in [0, 1]:
                logging.debug("[ Tipo de usuário inválido ]")
                return jsonify({"success": False, "message": "Tipo de usuário inválido. O tipo de usuário deve ser 0 ou 1."}), 400
            else:
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                try:
                    senha_hash_blake2b = hashlib.blake2b(new_user['senha'].encode()).hexdigest()  
                    cursor.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                            (new_user['nome'], new_user['registro'], new_user['email'], senha_hash_blake2b, new_user['tipo_usuario']))
                    conn.commit()
                    logging.debug("[ Novo usuário cadastrado! ]")
                    return code_response(logging.debug,"Novo usuário cadastrado com sucesso.",200)
                    #return jsonify({"success": True, "message": "Novo usuário cadastrado com sucesso."}), 200
                except sqlite3.IntegrityError as e:
                    logging.debug("Usuário já cadastrado com esse REGISTRO")
                    return jsonify({"success": False, "message": "O registro já está em uso. Por favor, escolha um registro diferente."}), 400 
                except sqlite3.Error as e:
                    logging.error(f"ERRO SQLITE3: {e}")
                    logging.error(f"Traceback: {traceback.format_exc()}")
                    return jsonify({"success": False, "message": "ERRO SQLITE3!"}), 400 
                except Exception as e:
                    return handle_exceptions(logging.error, e)
        else:
            logging.debug("[ Usuário comum está tentando cadastradar ]")
            return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 403
    except Exception as e:
        return handle_exceptions(logging.error, e)

@app.route('/usuarios', methods=['GET'])
@jwt_required()
@verify_token
def get_usuario():
    try:
        current_user = get_jwt_identity()
        if current_user:
            logging.debug("Usuário autenticado")
            user_info = get_user_info(current_user)
            logging.debug(f"Recebido pedido de listagem de usuários de: {user_info}")
            if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 (administrador)
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario")
                data = cursor.fetchall()
                usuarios = [{'id': row[0], 'nome': row[1], 'registro': row[2], 'email': row[3], 'tipo_usuario': row[4]} for row in data]
                for usuario in usuarios:
                    usuario.pop('senha', None)  # Remove a senha, se existir
                conn.close()
                logging.debug("[ Listar usuário com sucesso! ]")
                response = {
                    "usuarios": usuarios,
                    "success": True,
                    "message": "Usuários encontrados"
                }
                return jsonify(response), 200
            else:  # Se o tipo de usuário não for 1 (administrador), ele irá bloquear a consulta!
                logging.debug("[ Usuário coomum não pode listar ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 403
        else:
            logging.error("[ Não foi possível obter as informações do usuário ]")
            return jsonify({'message': 'Não foi possível obter as informações do usuário', 'success': False}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)

@app.route('/usuarios/<int:registro>', methods=['GET'])
@jwt_required()
@verify_token
def get_usuario_by_registro(registro):
    try:
        current_user = get_jwt_identity()
        if current_user:
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro):  # Verifica se pode buscar                logging.debug("Verificando permissões de acesso")
                user_info = get_user_info(current_user)
                logging.debug(f"Recebido pedido de listar o usuário {registro} de: {user_info}")
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario WHERE registro=?", (registro,))
                data = cursor.fetchone()
                if data:
                    usuario = {'id': data[0], 'nome': data[1], 'registro': data[2], 'email': data[3], 'tipo_usuario': data[4]}
                    conn.close()
                    logging.debug("[ Usuário encontrado! ]")
                    response = {
                        "usuario": usuario,
                        "success": True,
                        "message": "Usuário encontrado com sucesso."
                    }
                    return jsonify(response), 200
                else:
                    logging.debug("[ Usuário não encontrado ]")
                    return jsonify({"success": False, "message": "O usuário com o registro especificado não foi encontrado."}), 404
            else:
                logging.debug("[ Usuário comum não pode pesquisar outros ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 403
        else:
            logging.error('[ Acesso negado. Você não está autenticado. ]')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)

@app.route('/usuarios/<int:registro>', methods=['PUT'])
@jwt_required()
@verify_token
def atualizar_usuario(registro):
    try:
        current_user = get_jwt_identity()
        if current_user:
            logging.debug(f"Recebida solicitação de atualização para o usuário com registro {registro}")
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro):  
                logging.debug("Verificando permissões de atualização")

                dados_atualizados = request.get_json()

                if 'nome' in dados_atualizados and 'email' in dados_atualizados and 'senha' in dados_atualizados:

                    senha_hash_blake2b = hashlib.blake2b(dados_atualizados['senha'].encode()).hexdigest()  


                    conn = sqlite3.connect('project_data.db')
                    cursor = conn.cursor()

                    cursor.execute("UPDATE usuario SET nome=?, email=?, senha=? WHERE registro=?",
                                   (dados_atualizados['nome'], dados_atualizados['email'], senha_hash_blake2b, registro))

                    conn.commit()
                    conn.close()

                    logging.debug("[ Usuário atualizado! ]")
                    response = {
                        "success": True,
                        "message": "Usuário atualizado com sucesso."
                    }
                    return jsonify(response), 200
                else:
                    logging.debug("[ Parâmetros inválidos para atualização ]")
                    return jsonify({"success": False, "message": "Parâmetros inválidos para atualização."}), 400
            else:
                logging.debug("[ Acesso negado para atualização ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para atualizar este usuário."}), 403
        else:
            logging.error('[ Acesso negado. Você não está autenticado. ]')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)
    
@app.route('/usuarios/<int:registro>', methods=['DELETE'])
@jwt_required()
@verify_token
def deletar_usuario(registro):
    try:
        current_user = get_jwt_identity()
        if current_user:
            logging.debug(f"Recebida solicitação de deletar o usuário com registro {registro}")
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro):  
                logging.debug("Verificando permissões de deleção!")

                if current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro or current_user['tipo_usuario'] == 1 and int(current_user['registro']) == registro:
                    # Usuário está tentando deletar a si mesmo
                    conn = sqlite3.connect('project_data.db')
                    cursor = conn.cursor()

                    cursor.execute("DELETE FROM usuario WHERE registro=?", (registro,))

                    conn.commit()
                    conn.close()

                    # Realiza o logout após excluir o usuário
                    auth_header = request.headers.get('Authorization')
                    token = auth_header.split(" ")[1]
                    revoked_tokens.add(token)

                    logging.debug("[ Usuário deletado! Logout realizado com sucesso! ]")
                    return code_response(logging.debug, "Usuário deletado! Logout realizado com sucesso!", 200)

                elif int(current_user['tipo_usuario']) == int(1):
                    # Usuário administrador está deletando outro usuário
                    conn = sqlite3.connect('project_data.db')
                    cursor = conn.cursor()

                    cursor.execute("DELETE FROM usuario WHERE registro=?", (registro,))

                    conn.commit()
                    conn.close()

                    logging.debug("[ Usuário deletado! ]")
                    response = {
                        "success": True,
                        "message": "Usuário deletado com sucesso"
                    }
                    return jsonify(response), 200

                else:
                    logging.debug("[ Acesso negado para deleção ]")
                    return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para deletar este usuário."}), 403
            else:
                logging.debug("[ Acesso negado para deleção ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para deletar este usuário."}), 403
        else:
            logging.error('[ Acesso negado. Você não está autenticado. ]')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)

# Servidor Flask
if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000

    app.run(debug=True, port=port, host='0.0.0.0')
