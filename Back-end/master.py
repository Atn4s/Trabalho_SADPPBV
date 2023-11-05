import sqlite3
import hashlib
import os

# Verificar se o arquivo project_data.db já existe
if not os.path.exists('project_data.db'):
    # Se não existir, chame o script Tables.py para criar as tabelas
    os.system('python3 Tables.py')
else:

    def gerar_usuario():
    
        con = sqlite3.connect('project_data.db')
        cur = con.cursor()

        nome = "João Paulo"
        registro = "25000"
        email = "joaop@mail.com"

        senha_md5 = hashlib.md5("joaopaulo123".encode()).hexdigest()
        senha_v2 = hashlib.blake2b(senha_md5.encode()).hexdigest()
        tipo_usuario = 1  # 1 para o usuário administrador

        cur.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                    (nome, registro, email, senha_v2, tipo_usuario))

        con.commit()
        con.close()

    if __name__ == '__main__':
        gerar_usuario()
        print("Usuário ADM inserido!")
