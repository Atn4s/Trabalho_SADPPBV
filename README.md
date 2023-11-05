# Trabalho_SADPPBV
Repositório do trabalho: Sistema de Auxílio para Deslocamento a Pé de Pessoas com Baixa Visão (SADPPBV) para a disciplina AD36A - Tecnologias Cliente-Servidor.
# Como executá-lo?
O sistema é feito em Python (utilizando o Flask) para o Back-end e JQuery para o Front-end. Para executá-lo, é necessário seguir estes passos:
<br>
<br>
<b> 1 - Instalar os requisitos do sistema listados no arquivo requirements.txt: </b>
<br>
<i> pip install -r requirements.txt </i>
<br>
<br>
<b> 2 - Verificar se você possui as versões mais recentes das bibliotecas: </b>
<br>
<i> pip install --upgrade -r requirements.txt </i>
<br>
<br>
<b> 3 - Na pasta Back-end, há um pequeno arquivo em shell para criar as tabelas e adicionar o usuário administrador (criado para facilitar os testes) basta rodar bash Builder.sh </b>
<br>
<p> Se preferir, você pode inicializar as tabelas das seguintes formas: </p>
    <i> 3.1 - rodando o servidor puro maas ele nãao terá o usuário ADM! python3 servidor.py {porta} </i>
    <br>
    <i> 3.1.1 - python3 Tables.py -> irá criar as tabelas do sistema </i>
    <br>
    <i> 3.2 - python3 master.py -> irá criar as tabelas do sistema caso elas não existam (da mesma forma que Tables.py), na segunda execução: </i>
      <br>
    <i> 3.2.1 - python3 Tables.py -> irá criar as tabelas do sistema e, caso já existam, irá adicionar o usuário administrador </i>
<br>
<br>
<b> 4 - Após instalar os requisitos e criar as tabelas, basta executar: python3 servidor {porta desejada para o Back-end} </b>
<br>
<br>
<b> 5 - Na pasta Front-end, rode python3 servidor_front {porta} e abra-o, em seguida configure com o backend: IP, PORTA e a autenticação!. Aproveite o Sistema SADPPBV! </b>
<br>