import sqlite3
import hashlib
import jwt

def gerar_usuario():
    con = sqlite3.connect('project_data.db')
    cur = con.cursor()

    nome = "João Paulo"
    registro = "25000"
    email = "joaop@mail.com"
    senha = hashlib.sha512("joaopaulo123".encode()).hexdigest()  # Senha 'joaopaulo123' em SHA-512
    tipo_usuario = 1  # 1 para o usuário administrador

    cur.execute("INSERT INTO usuario (nome, registro, email, senha, tipo_usuario) VALUES (?, ?, ?, ?, ?)",
                (nome, registro, email, senha, tipo_usuario))

    con.commit()
    con.close()


if __name__ == '__main__':
    gerar_usuario()