#!/bin/bash

arquivo="usuarios_ativos.txt"

# Loop infinito
while true; do
    # Limpe a tela
    clear
    # Verifique se o arquivo existe
    if [ -e "$arquivo" ]; then
        # Carregue e exiba o conteúdo do arquivo
        conteudo=$(cat "$arquivo")
        echo "Conteúdo do arquivo:"
        echo "$conteudo"
    else
        echo "O arquivo não existe."
    fi

    # Aguarde 5 segundos
    sleep 5
done
