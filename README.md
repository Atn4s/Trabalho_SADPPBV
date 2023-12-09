# Trabalho_SADPPBV
Repositório do trabalho: Sistema de Auxílio para Deslocamento a Pé de Pessoas com Baixa Visão (SADPPBV) para a disciplina AD36A - Tecnologias Cliente-Servidor.
[![Licença](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

## Como executá-lo?
O sistema é feito em Python (utilizando o Flask) para o Back-end e Javascript (e um pouquinho de JQuery) para o Front-end, podendo ser executado pelo index.html ou se preferir em um servidor HTTP local via Python também! Para executar esse projeto, siga os passos:

<br>
<br>

<b> 1 - Instale os requisitos do sistema listados no arquivo requirements.txt: </b>

<i> pip install -r requirements.txt </i>

<br>
<br>

<b> 2 - Verifique se você possui as versões mais recentes das bibliotecas necessárias: </b>

<i> pip install --upgrade -r requirements.txt </i>

<br>
<br>

<b> 3 - Na pasta Back-end, há um pequeno arquivo em shell que já cria as tabelas e adiciona os pontos, segmentos e adiciona o usuário ADM (feito para facilitar os testes) basta rodar: </b>

<i> bash Builder.sh </i>

<br>
<br>

<b> 4 - Após instalar os requisitos e criar as tabelas, basta executar: </b>

<br> 

<i> python3 servidor.py {porta desejada para o Back-end} </i>

<br>
<br>

<b> 5 - Na pasta Front-end, execute: </b>

<br>

<i> python3 servidor_front.py {porta} </i>

<br>

<b> Abra-o através da url que será fornecida, em seguida, configure com as configurações do seu backend: IP, PORTA e utilize a autenticação fornecida no script Builder.sh! (você pode rodar localmente via index.html também se preferir) </b>

<br>
<br>

<b> Aproveite o Sistema SADPPBV! </b>

<br>
<br>

---
**Nota:**
Este projeto é licenciado sob os termos da [Licença Pública Geral GNU v3.0](https://www.gnu.org/licenses/gpl-3.0.html). Veja o arquivo [LICENSE](LICENSE) para mais detalhes.