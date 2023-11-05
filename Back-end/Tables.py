import sqlite3

def initialize_database():
    try:
        conn = sqlite3.connect('project_data.db')
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS usuario 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                          nome VARCHAR(100), 
                          registro INTEGER(7) NOT NULL UNIQUE, 
                          email VARCHAR(100), 
                          senha VARCHAR(150), 
                          tipo_usuario INTEGER)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS blacklist 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                          token TTL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS rota 
                          (idrota INTEGER PRIMARY KEY AUTOINCREMENT, 
                          nome_rota VARCHAR(100),
                          inicio VARCHAR(50),
                          fim VARCHAR(50))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS rotasegmento 
                          (id_rota INTEGER, 
                          id_segmento INTEGER, 
                          FOREIGN KEY(id_rota) REFERENCES rota(idrota), 
                          FOREIGN KEY(id_segmento) REFERENCES segmento(idsegmento), 
                          PRIMARY KEY(id_rota,id_segmento))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS segmento 
                          (idsegmento INTEGER PRIMARY KEY AUTOINCREMENT, 
                          nome VARCHAR(100), 
                          distancia INTEGER, 
                          direcao VARCHAR(20), 
                          partida VARCHAR(50), 
                          chegada VARCHAR(50), 
                          ordem INTEGER, 
                          status BOOLEAN)''')

        conn.commit()
        conn.close()

        print("Tabelas criadas com sucesso.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == '__main__':
    initialize_database()
