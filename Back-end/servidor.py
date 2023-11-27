import hashlib, sqlite3, sys, secrets, logging, coloredlogs,traceback, regex as re
from datetime import timedelta 
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity 
from flask_cors import CORS
from functools import wraps
import Tables

logging.basicConfig(level=logging.DEBUG) 
coloredlogs.install(level='DEBUG', fmt='%(asctime)s - %(levelname)s - %(message)s')
app = Flask('SADPPBV') 
CORS(app, resources={r"/*": {"origins": "*"}})  

# key = secrets.token_hex(32)
# csrf_value = secrets.token_hex(32)

# chaves caso precise testar reiniciando o servidor! Basta comentar as que estão acima e descomentar as abaixo
key = 'chavegeradaparatestesemflask'
csrf_value = 'chavegeradaparatestesemflask'

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
                    return jsonify({'message': 'Não autenticado. Faça login novamente.', 'success': False}), 401    # 401 NÃO AUTENTICADO!
                else:
                    logging.debug("[ Token válido ]")
                    return jwt_required()(f)(*args, **kwargs)  # Token é válido = 200 lá em baixo!
            else:
                logging.debug("[ Token de autenticação não encontrado ]")
                return jsonify({'message': 'Token de autenticação não encontrado', 'success': False}), 401  # 401 SEM TOKEN LOGO = NÃO AUTENTICADO!
        except Exception as e:
            logging.error(f"Erro: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'message': 'Erro ao processar a solicitação', 'success': False}), 400  
    return decorated_function

def get_user_info(current_user):
    info_keys = ['user_id', 'tipo_usuario', 'registro']
    user_info = {key: current_user.get(key, 'não informado') for key in info_keys}
    return user_info

def code_response(message, status_code):
    return jsonify({"success": True, "message": message}), status_code

def handle_exceptions(logger, e):
    logger(f"Erro: {e}")
    logger(f"Traceback: {traceback.format_exc()}")
    return jsonify({"success": False, "message": "Erro ao processar a solicitação"}), 400

#Rota para o usuário fazer login!
@app.route('/login', methods=['POST'])
def login():
    registro = request.json.get('registro', None)
    senha = request.json.get('senha', None)
    logging.debug(f"[ SOLICITAÇÃO! Pedido de login para o usuário: {registro}]")

    try:
        if not registro or not senha:
            logging.debug("[ ERRO! Credenciais inválidas, verifique suas informações ]")            
            return jsonify({"success": False, "message": "Credenciais inválidas"}), 401 # Não autenticado!

        senha_hash_blake2b = hashlib.blake2b(senha.encode()).hexdigest()  # Criptografa a senha em BLAKE2B 
        current_user = authenticate_user(registro, senha_hash_blake2b) # manda registro e senha para a função de autenticação do usuário
        if not current_user:
            logging.debug("[ ERRO! Credenciais inválidas! verifique seu REGISTRO e SENHA!]")
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
        logging.debug(f"[ RESPOSTA: Login Autorizado para: {registro} ]")
        return jsonify({"success": True, "message": "Login bem-sucedido", "token": token, "registro": registro}), 200 # Token e pode usar meu sistema!

    except Exception as e:
        return handle_exceptions(logging.error, e)
    
#Rota para o usuário fazer logout!
@app.route('/logout', methods=['POST'])
@jwt_required()
@verify_token
def fazer_logout():
    try:
        auth_header = request.headers.get('Authorization') # Obtenha o token JWT do header
        token = auth_header.split(" ")[1]  
        current_user = get_jwt_identity()
        user_info = get_user_info(current_user)
        logging.debug(f"[ SOLICITAÇÃO! Pedido de logout de: {user_info} ]")

        revoked_tokens.add(token) # Adicione o token à lista de tokens revogados logo não será possível reutiliza-lo!
        logging.debug(f"[ RESPOSTA: Logout de {user_info} Realizado com sucesso! ]")
        return code_response("Logout bem-sucedido!",200)
    except Exception as e:
        logging.error(f"Erro ao processar o logout: {e}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Erro ao processar a solicitação de logout"}), 400 

#Rota para o usuário cadastrar!
@app.route('/usuarios', methods=['POST'])
@jwt_required()
@verify_token
def cadastrar_usuario():
    current_user = get_jwt_identity()
    try:
        if current_user and current_user['tipo_usuario'] == 1:          
            user_info = get_user_info(current_user)
            logging.debug(f"[ SOLICITAÇÃO! Pedido o usuário de: {user_info} deseja cadastrar ]")
            
            new_user = request.json
            if not new_user:
                logging.debug("[ ERRO! Dados de usuário ausentes para cadastrar ]")
                return jsonify({"success": False, "message": "Dados de usuário ausentes. Por favor, forneça os dados necessários."}), 403 
            
            if not re.match(r'^\d+$', str(new_user.get('registro'))) and not re.match(r'^"\d+"$', str(new_user.get('registro'))):
                logging.debug("[ ERRO! O campo registro deve conter apenas números ]")
                return jsonify({
                    "success": False,
                    "message": "O campo registro deve conter apenas números. Por favor, insira um valor numérico."
                }), 403

            required_fields = ['nome', 'registro', 'email', 'senha', 'tipo_usuario']

            if any(new_user.get(field) in (None, '') for field in required_fields):
                logging.debug("[ ERRO! Dados de usuário ausentes ou em branco para cadastrar ]")
                return jsonify({"success": False, "message": "Dados de usuário ausentes ou em branco. Por favor, forneça os dados necessários."}), 403            
            elif not re.match(r'^[\p{L}\s]{3,}$', str(new_user.get('nome'))):
                logging.debug("[ ERRO! O campo nome deve conter apenas letras e ter no mínimo 3 caracteres ]")
                return jsonify({
                    "success": False,
                    "message": "O campo nome deve conter apenas letras e ter no mínimo 3 caracteres."
                }), 403
            elif not re.match(r'^\d{1,7}$', str(new_user.get('registro'))) or int(new_user.get('registro')) < 0:
                logging.debug("[ ERRO! O campo registro deve conter no máximo 7 dígitos e não pode ser negativo ]")
                return jsonify({
                    "success": False,
                    "message": "O campo registro deve conter no máximo 7 dígitos e não pode ser negativo."
                }), 403
            elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', str(new_user.get('email'))):
                logging.debug("[ ERRO! O campo email deve conter pelo menos um '@' e um '.' ]")
                return jsonify({
                    "success": False,
                    "message": "O campo email deve conter pelo menos um '@' e um '.'."
                }), 403
            elif new_user['senha'] == "d41d8cd98f00b204e9800998ecf8427e": 
                logging.debug("[ ERRO! O campo senha não pode ser branco ou nulo! ]")
                return jsonify({
                    "success": False,
                    "message": "O campo senha não pode ser branco ou nulo!"
                }), 403
            elif new_user['tipo_usuario'] not in [0, 1]:
                logging.debug("[ ERRO! Tipo de usuário inválido ]")
                return jsonify({"success": False, "message": "Tipo de usuário inválido. O tipo de usuário deve ser 0 ou 1."}), 403
            else:
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                try:
                    senha_hash_blake2b = hashlib.blake2b(new_user['senha'].encode()).hexdigest()  
                    cursor.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                            (new_user['nome'], new_user['registro'], new_user['email'], senha_hash_blake2b, new_user['tipo_usuario']))
                    conn.commit()
                    logging.debug("[ RESPOSTA: Novo usuário cadastrado! ]")
                    return code_response("Novo usuário cadastrado com sucesso.",200)
                except sqlite3.IntegrityError as e:
                    logging.debug("[ ERRO! Usuário já cadastrado com esse REGISTRO ]")
                    return jsonify({"success": False, "message": "O registro já está em uso. Por favor, escolha um registro diferente."}), 403 
                except sqlite3.Error as e:
                    logging.error(f"ERRO SQLITE3: {e}")
                    logging.error(f"Traceback: {traceback.format_exc()}")
                    return jsonify({"success": False, "message": "ERRO SQLITE3!"}), 400 
                except Exception as e:
                    return handle_exceptions(logging.error, e)
        else:
            logging.debug("[ ERRO! Usuário comum está tentando cadastradar ]")
            return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 403
    except Exception as e:
        return handle_exceptions(logging.error, e)

#Rota para o listar usuário!
@app.route('/usuarios', methods=['GET'])
@jwt_required()
@verify_token
def get_usuario():
    try:
        current_user = get_jwt_identity()
        if current_user:
            user_info = get_user_info(current_user)
            logging.debug(f"[ SOLICITAÇÃO! Listagem de usuários solicitado por: {user_info} ]")
            if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1:  # Verifica se o tipo de usuário é 1 (administrador)
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario")
                data = cursor.fetchall()
                usuarios = [{'id': row[0], 'nome': row[1], 'registro': row[2], 'email': row[3], 'tipo_usuario': row[4]} for row in data]
                for usuario in usuarios:
                    usuario.pop('senha', None)  # Remove a senha, se existir
                conn.close()
                logging.debug("[ RESPOSTA: Listar usuário com sucesso! ]")
                response = {
                    "usuarios": usuarios,
                    "success": True,
                    "message": "Usuários encontrados"
                }
                return jsonify(response), 200
            elif 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 0:  # Verifica se o tipo de usuário é 0 (comum)
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario WHERE registro=?", (current_user['registro'],))
                data = cursor.fetchone()
                if data:
                    usuarios = [{'id': data[0], 'nome': data[1], 'registro': data[2], 'email': data[3], 'tipo_usuario': data[4]}]
                    conn.close()
                    logging.debug("[ RESPOSTA: Listar usuário com sucesso! ]")
                    response = {
                        "usuarios": usuarios,
                        "success": True,
                        "message": "Usuários encontrados"
                    }
                    return jsonify(response), 200
            else:  
                logging.debug("[ ERRO! Usuário que não for [0] ou [1] não pode listar ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 403
        else:
            logging.error("[ ERRO! Não foi possível obter as informações do usuário ]")
            return jsonify({'message': 'Não foi possível obter as informações do usuário', 'success': False}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)

#Rota para o listar usuário apartir de um registro (ID)!
@app.route('/usuarios/<registro>', methods=['GET'])
@jwt_required()
@verify_token
def get_usuario_by_registro(registro):
    try:
        if registro.isdigit():
            registro = int(registro)  
        elif re.match("^[0-9]+$", registro):
            registro = int(registro)
        else:
            logging.debug("Registro inválido. Deve ser um número inteiro.")
            return jsonify({"success": False, "message": "Registro inválido. Deve ser um número inteiro."}), 403
        current_user = get_jwt_identity()
        if current_user:
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro):  
                user_info = get_user_info(current_user)
                logging.debug(f"[ SOLICITAÇÃO! listar o usuário {registro} solicitado por: {user_info} ]")
                conn = sqlite3.connect('project_data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT id, nome, registro, email, tipo_usuario FROM usuario WHERE registro=?", (registro,))
                data = cursor.fetchone()
                if data:
                    usuario = {'id': data[0], 'nome': data[1], 'registro': data[2], 'email': data[3], 'tipo_usuario': data[4]}
                    conn.close()
                    logging.debug("[ RESPOSTA: Usuário encontrado! ]")
                    response = {
                        "usuario": usuario,
                        "success": True,
                        "message": "Usuário encontrado com sucesso."
                    }
                    return jsonify(response), 200
                else:
                    logging.debug("[ ERRO! Usuário não encontrado ]")
                    return jsonify({"success": False, "message": "O usuário com o registro especificado não foi encontrado."}), 404
            else:
                logging.debug("[ ERRO! Usuário comum não pode pesquisar outros ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para acessar esta rota."}), 403
        else:
            logging.error('[ ERRO! Acesso negado. Você não está autenticado. ]')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)

#Rota para o atualizar o usuário apartir de um registro (ID)!
@app.route('/usuarios/<registro>', methods=['PUT'])
@jwt_required()
@verify_token
def atualizar_usuario(registro):
    try:
        if registro.isdigit():
            registro = int(registro) 
        elif re.match("^[0-9]+$", registro):
            registro = int(registro)
        else:
            logging.debug("Registro inválido. Deve ser um número inteiro.")
            return jsonify({"success": False, "message": "Registro inválido. Deve ser um número inteiro."}), 403
        current_user = get_jwt_identity()
        if current_user:
            logging.debug(f"[ SOLICITAÇÃO! Solicitação de atualização de cadastro para o usuário com registro {registro} ]")
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro):  
                dados_atualizados = request.get_json()

                if 'nome' in dados_atualizados and 'email' in dados_atualizados and 'senha' in dados_atualizados:
                    if not re.match(r'^[\p{L}\s]{3,}$', str(dados_atualizados['nome'])):
                        logging.debug("[ ERRO! O campo nome deve conter apenas letras e ter no mínimo 3 caracteres ]")
                        return jsonify({
                            "success": False,
                            "message": "O campo nome deve conter apenas letras e ter no mínimo 3 caracteres."
                        }), 403

                    elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', str(dados_atualizados['email'])):
                        logging.debug("[ ERRO! O campo email deve conter pelo menos um '@' e um '.' ]")
                        return jsonify({
                            "success": False,
                            "message": "O campo email deve conter pelo menos um '@' e um '.'."
                        }), 403

                    elif dados_atualizados['senha'] == "d41d8cd98f00b204e9800998ecf8427e": 
                        logging.debug("[ ERRO! O campo senha não pode ser branco ou nulo! ]")
                        return jsonify({
                            "success": False,
                            "message": "O campo senha não pode ser branco ou nulo!"
                        }), 403

                    senha_hash_blake2b = hashlib.blake2b(dados_atualizados['senha'].encode()).hexdigest()  

                    conn = sqlite3.connect('project_data.db')
                    cursor = conn.cursor()
                    cursor.execute("UPDATE usuario SET nome=?, email=?, senha=? WHERE registro=?",
                                   (dados_atualizados['nome'], dados_atualizados['email'], senha_hash_blake2b, registro))
                    rows_affected = cursor.rowcount  

                    if rows_affected > 0:
                        conn.commit()
                        conn.close()

                        logging.debug("[ RESPOSTA: Usuário atualizado! ]")
                        response = {
                            "success": True,
                            "message": "Usuário atualizado com sucesso."
                        }
                        return jsonify(response), 200                    
                    else:
                        logging.debug("[ ERRO! Usuário não encontrado ]")
                        return jsonify({"success": False, "message": "O usuário com o registro especificado não foi encontrado."}), 404
                else:
                    logging.debug("[ ERRO! Parâmetros inválidos para atualização ]")
                    return jsonify({"success": False, "message": "Parâmetros inválidos para atualização."}), 403
            else:
                logging.debug("[ ERRO! Acesso negado para atualização ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para atualizar este usuário."}), 403
        else:
            logging.error('[ ERRO! Acesso negado. Você não está autenticado. ]')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)
    
#Rota para deletar o usuário apartir de um registro (ID)!
@app.route('/usuarios/<registro>', methods=['DELETE'])
@jwt_required()
@verify_token
def deletar_usuario(registro):
    try:
        if registro.isdigit():
            registro = int(registro) 
        elif re.match("^[0-9]+$", registro):
            registro = int(registro)
        else:
            logging.debug("Registro inválido. Deve ser um número inteiro.")
            return jsonify({"success": False, "message": "Registro inválido. Deve ser um número inteiro."}), 403
        current_user = get_jwt_identity()
        if current_user:
            logging.debug(f"[ SOLICITAÇÃO! Deletar o usuário com registro {registro} ]")
            if current_user['tipo_usuario'] == 1 or (current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro):  
                if current_user['tipo_usuario'] == 0 and int(current_user['registro']) == registro or current_user['tipo_usuario'] == 1 and int(current_user['registro']) == registro:
                    # Usuário está tentando deletar a si mesmo
                    conn = sqlite3.connect('project_data.db')
                    cursor = conn.cursor()

                    cursor.execute("DELETE FROM usuario WHERE registro=?", (registro,))

                    conn.commit()
                    conn.close()

                    auth_header = request.headers.get('Authorization')
                    token = auth_header.split(" ")[1]
                    revoked_tokens.add(token)

                    logging.debug("[ RESPOSTA: Usuário deletado com sucesso! ]")
                    return code_response("Usuário deletado com sucesso!", 200)

                elif int(current_user['tipo_usuario']) == int(1):
                    # Usuário administrador está deletando outro usuário
                    conn = sqlite3.connect('project_data.db')
                    cursor = conn.cursor()

                    cursor.execute("DELETE FROM usuario WHERE registro=?", (registro,))

                    rows_affected = cursor.rowcount  
                    if rows_affected > 0:
                        conn.commit()
                        conn.close()

                        logging.debug("[ RESPOSTA: Usuário deletado! ]")
                        response = {
                            "success": True,
                            "message": "Usuário deletado com sucesso"
                        }
                        return jsonify(response), 200            
                    else:
                        logging.debug("[ ERRO! Usuário não encontrado ]")
                        return jsonify({"success": False, "message": "O usuário com o registro especificado não foi encontrado."}), 404
                else:
                    logging.debug("[ ERRO! Acesso negado para deleção ]")
                    return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para deletar este usuário."}), 403
            else:
                logging.debug("[ ERRO! Acesso negado para deleção ]")
                return jsonify({"success": False, "message": "Acesso negado. Você não tem permissão para deletar este usuário."}), 403
        else:
            logging.error('[ ERRO! Acesso negado. Você não está autenticado. ]')
            return jsonify({"success": False, "message": "Acesso negado. Você não está autenticado."}), 401
    except Exception as e:
        return handle_exceptions(logging.error, e)


###
### ROTAS E OUTRAS CONFIGURAÇÕES!
### 

# Rota para cadastrar pontos
@app.route('/pontos', methods=['POST'])
@jwt_required()
@verify_token
def cadastrar_ponto():
    try:
        current_user = get_jwt_identity()        
        logging.debug(f"[ SOLICITAÇÃO! Solicitação de cadastro de ponto, solicitado pelo usuário com {current_user} ]")

        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1: 
            nome = request.json.get('nome', None)

            if not nome:
                logging.debug(f"[ ERRO! Nome do ponto não fornecido ]")
                return jsonify({"success": False, "message": "Nome do ponto não fornecido"}), 400

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            # Verificar se o ponto já existe no banco (insensível a maiúsculas e minúsculas)
            cursor.execute("SELECT nome FROM ponto WHERE LOWER(nome) = LOWER(?)", (nome,))
            existing_point = cursor.fetchone()

            if existing_point:
                conn.close()
                logging.debug(f"[ RESPOSTA: ERRO! Ponto já existe: {nome} ]")
                return jsonify({"success": False, "message": "Ponto já existe"}), 400

            # Inserir um novo ponto na tabela de ponto
            cursor.execute("INSERT INTO ponto (nome) VALUES (?)", (nome,))

            conn.commit()
            conn.close()

            logging.debug(f"[ RESPOSTA: Ponto cadastrado com sucesso: {nome} ]")
            return jsonify({"success": True, "message": "Ponto criado com sucesso"}), 200
        else:
            logging.debug(f"[ RESPOSTA: ERRO! Usuário comum não pode cadastradar ponto!]")
            return jsonify({"success": False, "message": "Usuário comum não pode cadastradar ponto!"}), 403
    except Exception as e:
        return handle_exceptions(logging.error, e)

# Rota para listar todos os pontos
@app.route('/pontos', methods=['GET'])
@jwt_required()
@verify_token
def listar_pontos():
    try:
        current_user = get_jwt_identity()
        logging.debug(f"[ SOLICITAÇÃO! Solicitação de listagem de pontos, solicitado pelo usuário com {current_user} ]")
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1 or 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 0 : 

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            # Exemplo: Selecionar todos os pontos da tabela de pontos
            cursor.execute("SELECT * FROM ponto")
            pontos = cursor.fetchall()

            conn.close()

            # Formatar os resultados conforme necessário
            pontos_formatados = [{"ponto_id": ponto[0], "nome": ponto[1]} for ponto in pontos]

            logging.debug(f"[ RESPOSTA: Lista de pontos recuperada com sucesso ]")
            return jsonify({"success": True, "message": "Lista de pontos recuperada com sucesso", "pontos": pontos_formatados}), 200

    except Exception as e:
        return handle_exceptions(logging.error, e)

# Rota para obter detalhes de um ponto específico
@app.route('/pontos/<ponto_id>', methods=['GET'])
@jwt_required()
@verify_token
def obter_ponto(ponto_id):
    current_user = get_jwt_identity()        
    logging.debug(f"[ SOLICITAÇÃO! Listagem do ponto {ponto_id}, solicitado pelo usuário com {current_user} ]")
    try:
        if ponto_id.isdigit():
            ponto_id = int(ponto_id) 
        elif re.match("^[0-9]+$", ponto_id):
            ponto_id = int(ponto_id)
        else:
            logging.debug(f"[ ERRO! Ponto inválido. Deve ser um número inteiro! ]")
            return jsonify({"success": False, "message": "Ponto inválido. Deve ser um número inteiro."}), 403
        logging.debug(f"[ SOLICITAÇÃO! Solicitação de listar o ponto {ponto_id}, solicitado pelo usuário com {current_user} ]")

        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1 or 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 0 : 
            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            # Exemplo: Selecionar um ponto específico da tabela de segmento
            cursor.execute("SELECT * FROM ponto WHERE idponto=?", (ponto_id,))
            ponto = cursor.fetchone()

            conn.close()

            # Verificar se o ponto existe
            if ponto:
                ponto_formatado = {"ponto_id": ponto[0], "nome": ponto[1]}
                logging.debug(f"[ RESPOSTA: Detalhes do ponto {ponto_id} recuperados com sucesso ]")
                return jsonify({"success": True, "message": f"Detalhes do ponto {ponto_id} recuperados com sucesso", "ponto": ponto_formatado}), 200
            else:
                logging.debug(f"[ ERRO! Ponto {ponto_id} não encontrado ]")
                return jsonify({"success": False, "message": f"Ponto {ponto_id} não encontrado"}), 404

    except Exception as e:
        return handle_exceptions(logging.error, e)

# Rota para atualizar um ponto específico
@app.route('/pontos/<ponto_id>', methods=['PUT'])
@jwt_required()
@verify_token
def atualizar_ponto(ponto_id):
    current_user = get_jwt_identity()
    logging.debug(f"[ SOLICITAÇÃO! Solicitação de atualizar o ponto {ponto_id}, solicitado pelo usuário com {current_user} ]")
    try:
        if ponto_id.isdigit():
            ponto_id = int(ponto_id) 
        elif re.match("^[0-9]+$", ponto_id):
            ponto_id = int(ponto_id)
        else:
            logging.debug(f"[ ERRO! Ponto inválido. Deve ser um número inteiro! ]")
            return jsonify({"success": False, "message": "Ponto inválido. Deve ser um número inteiro."}), 403
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1: 
            nome = request.json.get('nome', None)

            if not nome:
                logging.debug("[ ERRO! Nome do ponto não fornecido ]")
                return jsonify({"success": False, "message": "Nome do ponto não fornecido"}), 400

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            # Exemplo: Atualizar um ponto específico na tabela de segmento
            cursor.execute("UPDATE ponto SET nome=? WHERE idponto=?", (nome, ponto_id))

             # Verificar quantas linhas foram afetadas
            if cursor.rowcount == 0:
                conn.close()
                logging.debug(f"[ ERRO! Ponto {ponto_id} não encontrado ]")
                return jsonify({"success": False, "message": f"Ponto {ponto_id} não encontrado"}), 404

            conn.commit()
            conn.close()

            logging.debug(f"[ RESPOSTA: Ponto {ponto_id} atualizado com sucesso ]")
            return jsonify({"success": True, "message": f"Ponto {ponto_id} atualizado com sucesso"}), 200
        else:
            logging.debug(f"[ ERRO! Usuário comum não pode atualizar ponto! ]")
            return jsonify({"success": False, "message": "Usuário comum não pode atualizar ponto!"}), 403

    except Exception as e:
        return handle_exceptions(logging.error, e)

# Rota para excluir um ponto específico
@app.route('/pontos/<ponto_id>', methods=['DELETE'])
@jwt_required()
@verify_token
def excluir_ponto(ponto_id):
    current_user = get_jwt_identity()
    logging.debug(f"[ SOLICITAÇÃO! Solicitação de excluir o ponto {ponto_id}, solicitado pelo usuário com {current_user} ]")
    try:
        if ponto_id.isdigit():
            ponto_id = int(ponto_id) 
        elif re.match("^[0-9]+$", ponto_id):
            ponto_id = int(ponto_id)
        else:
            logging.debug(f"[ ERRO! Ponto inválido. Deve ser um número inteiro! ]")
            return jsonify({"success": False, "message": "Ponto inválido. Deve ser um número inteiro."}), 403
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1: 
            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            # Exemplo: Excluir um ponto específico da tabela de segmento
            cursor.execute("DELETE FROM ponto WHERE idponto=?", (ponto_id,))

            # Verificar quantas linhas foram afetadas
            if cursor.rowcount == 0:
                conn.close()
                logging.debug(f"[ ERRO! Ponto {ponto_id} não encontrado ]")
                return jsonify({"success": False, "message": f"Ponto {ponto_id} não encontrado"}), 404

            conn.commit()
            conn.close()

            logging.debug(f"[ RESPOSTA: Ponto {ponto_id} removido com sucesso ]")
            return jsonify({"success": True, "message": f"Ponto {ponto_id} removido com sucesso"}), 200

        else:
            logging.debug(f"[ ERRO! Usuário comum não pode deletar ponto!]")
            return jsonify({"success": False, "message": "Usuário comum não pode deletar ponto!"}), 403

    except Exception as e:
        return handle_exceptions(logging.error, e)

# Rota para criar um novo segmento
@app.route('/segmentos', methods=['POST'])
@jwt_required()
@verify_token
def create_segmento():
    try:
        current_user = get_jwt_identity()
        logging.debug(f"[ SOLICITAÇÃO! Solicitação de cadastrar segmento, solicitado pelo usuário com {current_user} ]")
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1: 
            data = request.json

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            data['distancia'] = int(data['distancia'])

            if data['distancia'] <= 0 :
                logging.debug(f"[ ERRO! Distância deve ser maior que zero! ]")
                return jsonify({"success": False, "message": "Distância deve ser maior que zero"}), 403

             # Verificar se os pontos inicial e final existem
            cursor.execute("SELECT COUNT(*) FROM ponto WHERE idponto IN (?, ?)", (data['ponto_inicial'], data['ponto_final']))
            count = cursor.fetchone()[0]

            if count != 2:
                logging.debug(f"[ ERRO! Pontos inicial e/ou final não existem!]")
                return jsonify({"success": False, "message": "Pontos inicial e/ou final não existem"}), 403

            # Verificar se a distância é maior que zero

            if data['status'] not in [0, 1]:
                logging.debug(f"[ ERRO! Status Inválido OLHE PROTOCOLO 0 OU 1 ]")
                return jsonify({"success": False, "message": "Tipo de status inválido. O status de deve ser 0 ou 1."}), 403

            # Verificar se o segmento já existe
            cursor.execute('''SELECT COUNT(*) FROM segmento 
                              WHERE distancia = ? AND ponto_inicial = ? AND ponto_final = ?
                              AND status = ? AND direcao = ?''', (data['distancia'], data['ponto_inicial'], 
                                                                  data['ponto_final'], data['status'], data['direcao']))
            count_segmento = cursor.fetchone()[0]

            if count_segmento > 0:
                logging.debug(f"[ RESPOSTA: Esse segmento já existe! ]")
                return jsonify({"success": False, "message": "Segmento já existe"}), 403

            cursor.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
                            VALUES (?, ?, ?, ?, ?)''', (data['distancia'], data['ponto_inicial'], 
                                                        data['ponto_final'], data['status'], data['direcao']))
            conn.commit()

            logging.debug(f"[ RESPOSTA: Segmento criado com sucesso!]")
            return jsonify({'success': True, 'message': 'Segmento criado com sucesso'}), 200
        else:
            logging.debug(f"[ ERRO! Usuário comum não pode cadastradar segmento!]")
            return jsonify({"success": False, "message": "Usuário comum não pode cadastradar segmento!"}), 403
    except Exception as e:
        return handle_exceptions(logging.error, e)


# Rota para listar todos segmentos
@app.route('/segmentos', methods=['GET'])
@jwt_required()
@verify_token
def get_segmentos():    
    current_user = get_jwt_identity()
    logging.debug(f"[ SOLICITAÇÃO! Solicitação de listagem de segmentos, solicitado pelo usuário com {current_user} ]")
    conn = sqlite3.connect('project_data.db')
    cursor = conn.cursor()

    # Retrieve data from the database
    cursor.execute('''SELECT * FROM segmento''')
    segmentos = cursor.fetchall()

    # Convert data to the desired format
    result = [{'segmento_id': s[0], 'ponto_inicial': s[2], 'ponto_final': s[3],
               'status': int(s[4]), 'distancia': s[1], 'direcao': s[5]} for s in segmentos]

    logging.debug(f"[ RESPOSTA: Lista de todos os segmentos! ]")
    return jsonify({'segmentos': result, 'success': True, 'message': 'Lista de todos os segmentos'}), 200


# Rota para listar um segmento especifico 
@app.route('/segmentos/<segmento_id>', methods=['GET'])
@jwt_required()
@verify_token
def get_segmento(segmento_id):
    current_user = get_jwt_identity()
    logging.debug(f"[ SOLICITAÇÃO! Solicitação de listar o segmento {segmento_id}, solicitado pelo usuário com {current_user} ]")
    try:
        if segmento_id.isdigit():
            segmento_id = int(segmento_id) 
        elif re.match("^[0-9]+$", segmento_id):
            segmento_id = int(segmento_id)
        else:
            logging.debug(f"[ ERRO! Segmento inválido. Deve ser um número inteiro. ]")
            return jsonify({"success": False, "message": "Segmento inválido. Deve ser um número inteiro."}), 403
 
        # Add your authentication logic here if needed
        conn = sqlite3.connect('project_data.db')
        cursor = conn.cursor()
        # Retrieve data from the database
        cursor.execute('''SELECT * FROM segmento WHERE idsegmento = ?''', (segmento_id,))
        segmento = cursor.fetchone()

        if segmento:
            result = {'segmento': {'segmento_id': segmento[0], 'ponto_inicial': segmento[2],
                                'ponto_final': segmento[3], 'status': bool(segmento[4]),
                                'distancia': segmento[1], 'direcao': segmento[5]},
                    'success': True, 'message': 'Segmento encontrado'}
            
            logging.debug(f"[ RESPOSTA: Segmento encontrado! ]")
            return jsonify(result), 200
        else:
            logging.debug(f"[ RESPOSTA: Segmento não encontrado! ]")
            return jsonify({'success': False, 'message': 'Segmento não encontrado'}), 404
    except Exception as e:
        return handle_exceptions(logging.error, e)
    
# Rota para atualizar um segmento especifico
@app.route('/segmentos/<segmento_id>', methods=['PUT'])
@jwt_required()
@verify_token
def update_segmento(segmento_id):
    current_user = get_jwt_identity()
    logging.debug(f"[ SOLICITAÇÃO! Solicitação de atualizar o segmento {segmento_id}, solicitado pelo usuário com {current_user} ]")
    try:
        if segmento_id.isdigit():
            segmento_id = int(segmento_id) 
        elif re.match("^[0-9]+$", segmento_id):
            segmento_id = int(segmento_id)
        else:
            logging.debug(f"[ ERRO! Ponto inválido. Deve ser um número inteiro! ]")
            return jsonify({"success": False, "message": "Ponto inválido. Deve ser um número inteiro."}), 403
        
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1: 
            data = request.json

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

            data['distancia'] = int(data['distancia'])            

            if data['distancia'] <= 0 :
                logging.debug(f"[ ERRO: Distância deve ser maior que zero ]")
                return jsonify({"success": False, "message": "Distância deve ser maior que zero"}), 403

            # Update data in the database
            cursor.execute('''UPDATE segmento 
                            SET distancia=?, ponto_inicial=?, ponto_final=?, status=?, direcao=? 
                            WHERE idsegmento=?''', (data['distancia'], data['ponto_inicial'],
                                                    data['ponto_final'], data['status'], data['direcao'], segmento_id))
            conn.commit()

            logging.debug(f"[ RESPOSTA: Segmento atualizado com sucesso ]")
            return jsonify({'success': True, 'message': 'Segmento atualizado com sucesso'}), 200
        else:
            logging.debug(f"[ ERRO! Usuário comum não pode atualizar segmento!]")
            return jsonify({"success": False, "message": "Usuário comum não pode atualizar segmento!"}), 403
    except Exception as e:
        return handle_exceptions(logging.error, e)     


# Routa para deletar um segmento especifico
@app.route('/segmentos/<segmento_id>', methods=['DELETE'])
@jwt_required()
@verify_token
def delete_segmento(segmento_id):
    current_user = get_jwt_identity()
    logging.debug(f"[ SOLICITAÇÃO! Solicitação de deletar o segmento {segmento_id}, solicitado pelo usuário com {current_user} ]")
    try:
        if segmento_id.isdigit():
            segmento_id = int(segmento_id) 
        elif re.match("^[0-9]+$", segmento_id):
            segmento_id = int(segmento_id)
        else:
            logging.debug(f"[ ERRO! Ponto inválido. Deve ser um número inteiro. ]")
            return jsonify({"success": False, "message": "Ponto inválido. Deve ser um número inteiro."}), 403
        
        if 'tipo_usuario' in current_user and current_user['tipo_usuario'] == 1: 

            conn = sqlite3.connect('project_data.db')
            cursor = conn.cursor()

             # Verificar se o segmento existe antes de excluir
            cursor.execute("SELECT * FROM segmento WHERE idsegmento=?", (segmento_id,))
            segmento = cursor.fetchone()

            if not segmento:
                logging.debug(f"[ RESPOSTA: Segmento não encontrado ]")
                return jsonify({'success': False, 'message': 'Segmento não encontrado'}), 404

            # Delete data from the database
            cursor.execute('''DELETE FROM segmento WHERE idsegmento=?''', (segmento_id,))
            conn.commit()

            logging.debug(f"[ RESPOSTA: Segmento removido com sucesso ]")
            return jsonify({'success': True, 'message': 'Segmento removido com sucesso'}), 200
        else:
            logging.debug(f"[ ERRO! Usuário comum não pode apagar segmento!]")
            return jsonify({"success": False, "message": "Usuário comum não pode apagar segmento!"}), 403
    except Exception as e:
        return handle_exceptions(logging.error, e)     

###
### Servidor Flask
###

if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000

    app.run(debug=True, port=port, host='0.0.0.0')