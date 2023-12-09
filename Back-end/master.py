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
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e1_inicio",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e1_fim",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Capela",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e2_inicio",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e2_fim",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.6",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.7",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.8",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e4_inicio",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e4_fim",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("laCA",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("r1_inicio",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("r1_fim",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Auditório",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e3_inicio",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("e3_fim",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.1",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.3",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.5",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("DAINF",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.2",))
       cur.execute("INSERT INTO ponto (nome) VALUES (?)", ("Lab.4",))

       # portaria a escada e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (100.0, 1, 2, 1, "Siga em Frente por 100 metros"))

       # escada inicio para fim escada e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (3.0, 2, 3, 1, "Utilize a escada, CUIDADO COM DEGRAUS"))

       # escada fim para capela e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (5.0, 3, 4, 1, "[E1_FIM PARA CAPELA] Siga em Frente por 5 metros, a sua frente está a Capela, a esquerda há um corredor para o Auditório e a sua direita há outro corredor para os laboratórios. [CAPELA PARA E1_FIM] Siga em Frente por 5 metros."))

       # capela para e2_inicio e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (20.0, 4, 5, 1, "[CAPELA PARA E2_INICIO] Caso a Capela esteja a sua frente Vire à direita e Siga em frente por 20 metros. Haverá uma escada à sua esquerda. [E2_INICIO PARA CAPELA] Há uma escada à sua direita. Siga em frente por 20 metros."))

       # e2_inicio para Lab.6 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (2.0, 5, 7, 1, "[E2_INICIO.6 PARA LAB.6] Siga em frente por 2 metros, a sua frente é o LAB.6 e a sua esquerda há um corredor para outros laboratórios. [LAB.6 PARA E2_INICIO] em sua direita há um corredor, Siga em Frente por 2 metros"))
        
       # Lab.6 para Lab.7 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (20.0, 7, 8, 1, "[LAB.6 PARA LAB.7] Caso esteja em frente ao LAB.6 Vire à esquerda e siga em frente por 20 metros. Você estará em frente ao Lab.7. [LAB.7 PARA LAB.6] Siga em frente por 20 metros. Você estará em frente ao Lab.6, à sua direita há um corredor"))
        
       # Lab.7 para Lab.8 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (10.0, 8, 9, 1, "Siga em Frente por 10 metros"))

       # Lab.8 para e4_inicio e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (5.0, 9, 10, 1, "[LAB.8 PARA E4_INICIO] Siga em frente por 5 metros e vire à esquerda. Você estará em frente a uma escada.[E4_INICIO PARA LAB.8] Vire à direita e siga em frente por 5 metros. Você estará em frente ao Lab.8."))      
       
       # e4_inicio para e4_fim e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (1.0, 10, 11, 1, "Utilize a escada, CUIDADO COM DEGRAUS"))

       #e4_fim para LaCA e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (2.0, 11, 12, 1, "Siga em frente por 2 metros"))

       #LaCA para r1_fim e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (40.0, 12, 14, 1, "[LACA PARA R1_FIM] Siga em frente por 40 metros. Haverá uma rampa à sua esquerda. [R1_FIM PARA LACA] Vire à direita e siga em frente por 40 metros. Você estará em frente ao LaCA."))      

       #r1_inicio para r1_fim e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (1.0, 13, 14, 1, "[R1_INICIO SUBINDO] Fique à direita e suba a rampa. [R1_FIM DESCENDO] Fique à esquerda e desça a rampa.")) 

       #r1_inicio para Auditório  e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (35.0, 13, 15, 1, "[R1_INICIO PARA AUDITÓRIO] Permaneça à esquerda e ande por 35 metros. O Auditório estará à sua direita, e à sua esquerda há um corredor para a CAPELA. [AUDITÓRIO PARA R1_INICIO] Se o Auditório está a sua esquerda permaneça à direita e ande para frente por 35 metros. Haverá uma rampa à sua frente."))       

       #Auditório para Capela e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (20.0, 15, 4, 1, "[AUDITÓRIO PARA CAPELA] Se o AUDITÓRIO está a sua direita Vire a Esquerda e Siga em Frente por 20 metros. [CAPELA PARA AUDITÓRIO] Se a Capela está em sua frente Vire a Esquerda e Siga em Frente por 20 metros"))       

       #Auditório para e3_inicio e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (2.0, 15, 16, 1, "[AUDITÓRIO PARA ESCADA] Se o AUDITÓRIO está a sua direita Siga em frente por 2 metros. Haverá uma escada à sua frente. [ESCADA PARA AUDITÓRIO] Siga em frente por 2 metros. À sua esquerda é o Auditório, à sua direita é um corredor para a CAPELA, e à sua frente é outro corredor."))

       #e3_inicio para e3_fim (subindo) e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (10.0, 16, 17, 1, "Utilize a escada se apoiando ao corrimão! ela é em formato de U"))

       #e2_inicio para e2_fim (subindo) e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (10.0, 5, 6, 1, "Utilize a escada se apoiando ao corrimão! ela é em formato de U"))      

       #e2_fim para Lab.1 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (2.0, 6, 18, 1, "[E2_FIM PARA LAB.1] Ao subir a escada Vire à esquerda e ande em frente por 2 metros. Você estará em frente ao Lab.1. [LAB.1 PARA E2_FIM] Ande em frente por 2 metros. À sua direita, estará a escada para descer."))       

       #Lab.1 para Lab.3 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (2.0, 18, 19, 1, "[LAB.1 PARA LAB.3] Siga em frente por 2 metros, você vai estar em frente ao LAB.3, a sua esquerda há um corredor. [LAB.3 PARA LAB.1] Se o LAB.3 está atrás de você Siga em frente por 2 metros, você vai estar em frente ao LAB.1 "))

       #Lab.3 para Lab.5 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (10.0, 19, 20, 1, "[LAB.3 PARA LAB.5] Se estiver em frente ao LAB.3 Vire à esquerda e siga em frente por 10 metros. Você estará em frente ao Lab.5. [LAB.5 PARA LAB.3] Siga em frente por 10 metros. Você estará em frente ao Lab.3, à sua Direita há um corredor."))     

       #Lab.5 para Dainf e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (15.0, 20, 21, 1, "Siga em frente por 15 metros"))

       #e2_fim para Lab.2 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (3.0, 6, 22, 1, "[E2_FIM PARA LAB.2] Ao subir a escada  Vire à direita e siga em frente por 3 metros. Você estará em frente ao Lab.2. [LAB.2 PARA E2_FIM] Siga em frente por 3 metros. À sua esquerda, haverá uma escada para descer."))      

       #Lab.2 para Lab.4 e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (5.0, 22, 23, 1, "Siga em frente por 5 metros"))

       #Lab.4 para e3_fim e vice-versa
       cur.execute('''INSERT INTO segmento (distancia, ponto_inicial, ponto_final, status, direcao) 
              VALUES (?, ?, ?, ?, ?)''', (30.0, 23, 17, 1, "[LAB.4 PARA E3_FIM] Ande em frente por 30 metros. À sua esquerda, haverá uma escada para descer. [E3_FIM PARA LAB.4] Ao subir a escada Vire à direita e siga em frente por 30 metros. Você estará em frente ao Lab.4."))       

       con.commit()
       con.close()

    if __name__ == '__main__':
        gerar_usuario()
        print("Usuário ADM, pontos e segmentos foram inseridos em sua base! Tudo pronto para usar!")
