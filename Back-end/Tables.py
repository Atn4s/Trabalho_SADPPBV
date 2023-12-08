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

        cursor.execute('''CREATE TABLE IF NOT EXISTS ponto 
                          (idponto INTEGER PRIMARY KEY AUTOINCREMENT, 
                          nome VARCHAR(100))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS segmento 
                          (idsegmento INTEGER PRIMARY KEY AUTOINCREMENT, 
                          distancia REAL, 
                          ponto_inicial INTEGER,
                          ponto_final INTEGER,
                          status BOOLEAN,
                          direcao VARCHAR(250),
                          FOREIGN KEY(ponto_inicial) REFERENCES ponto(idponto),
                          FOREIGN KEY(ponto_final) REFERENCES ponto(idponto))''')      

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == '__main__':
    initialize_database()
