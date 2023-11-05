# Trabalho_SADPPBV
Repositório do trabalho: Sistema de Auxílio para Deslocamento a Pé de Pessoas com Baixa Visão (SADPPBV) para a disciplina AD36A - Tecnologias Cliente-Servidor.
# Como executá-lo?
O sistema é feito em Python (utilizando o Flask) para o Back-end e JQuery para o Front-end podendo ser executado em um servidor HTTP em python também!. Para executá-lo siga os passos:
<br>
<br>
<b> 1 - Instale os requisitos do sistema listados no arquivo requirements.txt: </b>
<br>
<i> pip install -r requirements.txt </i>
<br>
<br>
<b> 2 - Verifique se você possui as versões mais recentes das bibliotecas necessárias: </b>
<br>
<i> pip install --upgrade -r requirements.txt </i>
<br>
<br>
<b> 3 - Na pasta Back-end, há um pequeno arquivo em shell que já cria as tabelas e adiciona o usuário ADM (feito para facilitar os testes) basta rodar: </b> 
<br> 
<i> bash Builder.sh </i>
<br>
<p> Ou se preferir, você pode inicializar as tabelas das seguintes formas: </p>
<p> Opção 1:</p>
    <i> 3.1 - Através do servidor puro mas, ele não terá o usuário ADM! python3 servidor.py {porta} </i>
    <br>
    <i> 3.1.1 - Em outro terminal utilize o seguinte código para adicionar o usuário ADM: python3 master.py</i>
    <br>
    <br>
<p> Opção 2:</p>
    <i> 3.2 - python3 Tables.py -> irá criar as tabelas do sistema </i>
    <br>
    <i> 3.2.1 - Em outro terminal o seguinte código para adicionar o usuário ADM: python3 master.py</i>
    <br>
    <br>
<p> Opção 3:</p>
    <i> 3.3 - python3 master.py -> irá criar as tabelas do sistema caso elas não existam (da mesma forma que Tables.py), na segunda execução: </i>
      <br>
    <i> 3.3.1 - python3 master.py -> irá criar as tabelas do sistema e, caso já existam, irá adicionar o usuário ADM </i>
<br>
<br>
<b> 4 - Após instalar os requisitos e criar as tabelas, basta executar: </b> <br> <i> python3 servidor.py {porta desejada para o Back-end} </i> 
<br>
<br>
<b> 5 - Na pasta Front-end, execute: </b> <br> <i> python3 servidor_front.py {porta} </i> <br> <b> abra-o, em seguida configure com o backend: IP, PORTA e a autenticação!. Aproveite o Sistema SADPPBV! </b>
<br>
