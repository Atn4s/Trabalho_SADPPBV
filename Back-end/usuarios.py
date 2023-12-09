import time
import os

arquivo = "usuarios_ativos.txt"

# Loop infinito
while True:
    # Limpe a tela
    os.system("clear" if os.name == "posix" else "cls")

    # Verifique se o arquivo existe
    if os.path.exists(arquivo):
        # Carregue e exiba o conteúdo do arquivo
        with open(arquivo, "r") as file:
            conteudo = file.read()
            print("Conteúdo do arquivo:")
            print(conteudo)
    else:
        print("O arquivo não existe.")

    # Aguarde 5 segundos
    time.sleep(5)