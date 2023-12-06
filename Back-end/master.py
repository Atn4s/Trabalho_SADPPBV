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

        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Portaria principal",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e1",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Capela",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e2",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.6",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.7",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.8",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e4",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("laCA",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("r1",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Auditório",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e3",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("1.o Andar",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Andar Térreo",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.1",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.3",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.5",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("DAINF",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.2",))
        cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.4",))

        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (100.0, 1, 2, 1, "Frente"))

        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (5.0, 2, 3, 1, "Suba"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (20.0, 3, 4, 1, "Vire a Direita"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (2.0, 4, 5, 1, "Siga em Frente"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (20.0, 5, 6, 1, "Vire a Esquerda"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (10.0, 6, 7, 1, "Siga em Frente"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (5.0, 7, 8, 1, "Siga em Frente"))

        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (2.0, 8, 9, 1, "Suba"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (40.0, 9, 10, 1, "Siga em Frente"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (35.0, 10, 11, 1, "Vire e Mantenha-se a Esquerda"))
        
        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (35.0, 10, 11, 1, "Vire e Mantenha-se a Esquerda"))

        cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
               VALUES (?, ?, ?, ?, ?)''', (20.0, 11, 3, 1, "Vire a Esquerda"))

        con.commit()
        con.close()

    if __name__ == '__main__':
        gerar_usuario()
        print("Usuário ADM inserido!")
