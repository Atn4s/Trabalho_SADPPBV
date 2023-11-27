let IP = localStorage.getItem('IP');
let PORT = localStorage.getItem('PORT');
let token = localStorage.getItem('token');
let registroGlobal;
let tbody = [];

    function limparTela() {
        clearFields();
        clearTable();
        localStorage.removeItem('token'); // Remova o token do localStorage ao fazer logout
        localStorage.removeItem('IP'); // Remova o IP do localStorage ao fazer logout
        localStorage.removeItem('PORT'); // Remova o PORT do localStorage ao fazer logout
        location.reload(); // Recarrega a página após a exclusão
    }

    if (token) {
        $('#options').show(); // Use o método .show() para exibir o elemento
        $('#loginForm').hide(); // Use o método .hide() para ocultar o elemento
    }

    function solicitarIDUsuario() {
        let id = prompt('Digite o REGISTRO do usuário:');
        if (id) {
            id = id.replace(/^0+/, ''); // Remove os zeros à esquerda da string
            listarUsuarioPorID(id);
        } else {
            alert("O ID do usuário não pode ser vazio.");
        }
    }

    function clearFields() {
        $('#ip').val('');
        $('#port').val('');
        $('#registro').val('');
        $('#senha').val('');
    }
    
    function clearTable() {
        const table = document.getElementById('tableUsuarios');
        if (table) {
            table.innerHTML = '';
        }
    }

    function clearTabela() {
        const table = document.getElementById('tablePontos');
        if (table) {
            table.innerHTML = '';
        }
    }

    function clearTabela3() {
        const table = document.getElementById('tableSegmentos');
        if (table) {
            table.innerHTML = '';
        }
    }

    function clearTabela2() {
        const table = document.getElementById('tablePontos');
        if (table) {
            const tbody = table.querySelector('tbody');
            if (tbody) {
                while (tbody.firstChild) {
                    tbody.removeChild(tbody.firstChild);
                }
            }
        }
    }

    if (IP && PORT) {
        $('#options').css('display', 'block');
        $('#loginForm').css('display', 'none');
    }

    $('#login').submit(function (event) {
        event.preventDefault();
        IP = $('#ip').val();
        PORT = $('#port').val();

        // Verificar se os campos de IP e PORT não estão vazios
        if (IP && PORT) {
            const registro = $('#registro').val();
            const senha = md5($('#senha').val());

            $.ajax({
                url: `http://${IP}:${PORT}/login`,
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    registro: parseInt(registro),
                    senha: senha
                }),
                success: function (response) {
                    console.log(response);
                    token = response.token;
                    localStorage.setItem('IP', IP);
                    localStorage.setItem('PORT', PORT);
                    localStorage.setItem('token', token);
                    $('#options').css('display', 'block');
                    $('#loginForm').css('display', 'none');
                    registroGlobal = registro;
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));                
                }
            });
        } else {
            alert("IP e PORT devem ser preenchidos");
        }
    });

    function fazerLogout() {
        $.ajax({
            url: `http://${IP}:${PORT}/logout`,
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            success: function (response) {
                console.log(response);
                clearFields();
                clearTable(); // Limpa a tabela de usuários ao fazer logout
                clearTabela();
                localStorage.removeItem('token'); // Remova o token do localStorage ao fazer logout
                localStorage.removeItem('IP'); // Remova o IP do localStorage ao fazer logout
                localStorage.removeItem('PORT'); // Remova o PORT do localStorage ao fazer logout
                $('#options').hide(); // Use o método .hide() para ocultar o elemento
                $('#loginForm').show(); // Use o método .show() para exibir o elemento
            },
            error: function (error) {
                const errorObject = JSON.parse(error.responseText);
                alert(JSON.stringify(errorObject));
            }
        });
    }

    let tableVisible = false; // Variável para controlar a visibilidade da tabela
    let table; // Variável para a tabela

    function toggleTable(tableId, show) {
        let table = document.getElementById(tableId);
        if (table) {
            if (show) {
                table.style.display = 'block'; // Mostra a tabela
                tableVisible = true;
            } else {
                table.style.display = 'none'; // Esconde a tabela
                tableVisible = false;
            }
        } else {
            console.error('Tabela não encontrada com o ID:', tableId);
        }
    }

    function addButtons(row, usuario) {
        const updateButton = document.createElement('button');
        updateButton.innerHTML = 'Atualizar';
        updateButton.onclick = function() {
            const novoNome = prompt('Digite o novo nome:', usuario.nome);
            const novoEmail = prompt('Digite o novo email:', usuario.email);
            const novaSenha = prompt('Digite a nova senha:', usuario.senha);
    
            const senhaMD5 = md5(novaSenha);

            if (novoNome && novoEmail && senhaMD5) {
                const dadosAtualizados = {
                    nome: novoNome,
                    email: novoEmail,
                    senha: senhaMD5
                };
                    
                $.ajax({
                    url: `http://${IP}:${PORT}/usuarios/${usuario.registro}`,
                    type: 'PUT',
                    contentType: 'application/json',
                    data: JSON.stringify(dadosAtualizados),
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    success: function (response) {
                        alert(JSON.stringify(response));
                    },

                    error: function (error) {
                        try {
                            const errorObject = JSON.parse(error.responseText);
                            alert(JSON.stringify(errorObject));
                        } catch (e) {
                            console.log("Erro ao analisar JSON da resposta de erro:", e);
                            alert("Erro desconhecido ao processar a resposta de erro.");
                        }                  
                    }
                });
            } else {
                alert('Por favor, preencha todos os campos. Atualização cancelada.');
            }
        };
        row.appendChild(updateButton);
    
        const deleteButton = document.createElement('button');
        let vaideletar=false;
        const registroUsuarioASerExcluido = usuario.registro;

        if (parseInt(registroGlobal) == parseInt(registroUsuarioASerExcluido)) 
        {
            vaideletar = true;
        }

        deleteButton.innerHTML = 'Excluir';
        deleteButton.onclick = function() {
            $.ajax({
                url: `http://${IP}:${PORT}/usuarios/${usuario.registro}`,
                type: 'DELETE',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                success: function (response) {
                    alert(JSON.stringify(response));
                    if (vaideletar == true) {
                        alert("Seu usuário foi deletado do sistema! Voltando a tela inicial!");
                        limparTela();
                    }
                },

                error: function (error) {
                    try {
                        const errorObject = JSON.parse(error.responseText);
                        alert(JSON.stringify(errorObject));
                    } catch (e) {
                        console.log("Erro ao analisar JSON da resposta de erro:", e);
                        alert("Erro desconhecido ao processar a resposta de erro.");
                    }                  
                }
            });
        };
        row.appendChild(deleteButton);
    }

    function listarUsuarios() {
    if (!tableVisible) {
    $.ajax({
        url: `http://${IP}:${PORT}/usuarios`,
        type: 'GET',
        contentType: 'application/json',
        headers: {
            'Authorization': `Bearer ${token}`
        },
        success: function (response) {
            console.log(response);
            if (response && (response.usuarios || response.usuario)) {
                const usuarios = response.usuarios ? response.usuarios : [response.usuario]; // Verifica se há vários usuários ou apenas um

                clearTable(); // Limpa a tabela antes de adicionar novos dados

                table = document.getElementById('tableUsuarios');
                if (!table) {
                    table = document.createElement('table');
                    table.id = 'tableUsuarios';
                    document.body.appendChild(table);
                }

                const thead = table.createTHead();
                const row = thead.insertRow();
    
                // Cabeçalho 1: nome
                const th1 = document.createElement('th');
                th1.innerHTML = 'Nome';
                row.appendChild(th1);
    
                // Cabeçalho 2: registro
                const th2 = document.createElement('th');
                th2.innerHTML = 'Registro';
                row.appendChild(th2);
    
                // Cabeçalho 3: email
                const th3 = document.createElement('th');
                th3.innerHTML = 'Email';
                row.appendChild(th3);
    
                // Cabeçalho 4: tipo_usuario
                const th4 = document.createElement('th');
                th4.innerHTML = 'Tipo de Usuário';
                row.appendChild(th4);

                const tableBody = document.createElement('tbody');
                for (let i = 0; i < usuarios.length; i++) {
                    const usuario = usuarios[i];
                    const row = tableBody.insertRow(i);

                    const cell1 = row.insertCell(0);
                    cell1.innerHTML = usuario.nome;

                    const cell2 = row.insertCell(1);
                    cell2.innerHTML = usuario.registro;

                    const cell3 = row.insertCell(2);
                    cell3.innerHTML = usuario.email;

                    const cell4 = row.insertCell(3);
                    cell4.innerHTML = usuario.tipo_usuario === 1 ? 'Administrador' : 'Usuário Comum';

                    addButtons(row, usuario); // Adiciona botões para cada linha de usuário
                }                
                
                table.appendChild(tableBody);
                toggleTable('tableUsuarios', true); // Mostra a tabela de usuários
            } else {
                alert("Nenhum usuário encontrado.");
            }            
        },
        error: function (error) {
            const errorObject = JSON.parse(error.responseText);
            alert(JSON.stringify(errorObject));
        }
        });
        } else {
            clearTable(); // Limpa a tabela antes de ocultar
            tableVisible = false; // Define a tabela como oculta
            toggleTable('tableUsuarios', false); // Mostra a tabela de usuários
            // toggleTable(false); // Esconde a tabela
        }
    }

    function listarUsuarioPorID(id) {
        if (token) {
            $.ajax({
                url: `http://${IP}:${PORT}/usuarios/${id}`,
                type: 'GET',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                success: function (response) {
                    let usuario;
                    console.log(response);
                    if (response && response.usuario || response.usuarios) {
                        if(response && response.usuario){
                            usuario = response.usuario;
                        }
                        else if (response && response.usuarios){
                            usuario = response.usuarios;
                        }                                        
                        clearTable();
    
                        let table = document.getElementById('tableUsuarios');
                        if (!table) {
                            table = document.createElement('table');
                            table.id = 'tableUsuarios';
                            document.body.appendChild(table);
                        }
    
                        const thead = table.createTHead();
                        const row = thead.insertRow();
    
                        // Cabeçalho 1: nome
                        const th1 = document.createElement('th');
                        th1.innerHTML = 'Nome';
                        row.appendChild(th1);
    
                        // Cabeçalho 2: registro
                        const th2 = document.createElement('th');
                        th2.innerHTML = 'Registro';
                        row.appendChild(th2);
    
                        // Cabeçalho 3: email
                        const th3 = document.createElement('th');
                        th3.innerHTML = 'Email';
                        row.appendChild(th3);
    
                        // Cabeçalho 4: tipo_usuario
                        const th4 = document.createElement('th');
                        th4.innerHTML = 'Tipo de Usuário';
                        row.appendChild(th4);
    
                        const tableBody = document.createElement('tbody');
                        const newRow = tableBody.insertRow(0);
    
                        const cell1 = newRow.insertCell(0);
                        cell1.innerHTML = usuario.nome;
    
                        const cell2 = newRow.insertCell(1);
                        cell2.innerHTML = usuario.registro;
    
                        const cell3 = newRow.insertCell(2);
                        cell3.innerHTML = usuario.email;
    
                        const cell4 = newRow.insertCell(3);
                        cell4.innerHTML = usuario.tipo_usuario === 1 ? 'Administrador' : 'Usuário Comum';
    
                        addButtons(row, usuario); // Adiciona botões para cada linha de usuário

                        table.appendChild(tableBody);
                        toggleTable('tableUsuarios', true); // Mostra a tabela de usuários
                        //toggleTable(true);
                    } else {
                        alert("Usuário não encontrado.");
                    }
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
        } else {
            alert("Faça login para executar esta ação.");
        }
    }
    
    function criarUsuario() {
        let nome;
        while(!nome || !nome.trim()){
            nome = prompt('Informe o NOME do usuário:');
            if(!nome || !nome.trim()){
                alert("Insira um NOME válido!")
            }
        }

        let registro;
        while(!registro || !registro.trim()){
            registro = prompt('Informe o REGISTRO para o usuário:');
            if(!registro || !registro.trim()){
                alert("Insira um REGISTRO válido!")
            }
        }

        let registroInt = parseInt(registro, 10); // Converte para inteiro

        let email;
        while(!email || !email.trim()){
            email = prompt('Informe o EMAIL para o usuário:');
            if(!email || !email.trim()){
                alert("Insira um EMAIL válido!")
            }
        }

        let senha;
        while(!senha || !senha.trim()){
            senha = prompt('Informe a SENHA para o usuário:');
            if(!senha || !senha.trim()){
                alert("Insira uma SENHA válido!")
            }
        }

        let tipo_usuario;
        while(tipo_usuario !== "0" && tipo_usuario !== "1"){
            tipo_usuario = prompt('Informe a TIPO DE USUÁRIO: [1 - ADMINISTRADOR] - [0 - COMUM]');
            if(tipo_usuario !== "0" && tipo_usuario !== "1") {
                alert("USUÁRIO PODE SER APENAS 0 OU 1!")
            }
        }

        let tipo_usuarioInt = parseInt(tipo_usuario, 10); // Converte para inteiro
        const senhaMD5 = md5(senha);
    
        const novoUsuario = {
            nome: nome,
            registro: registroInt,
            email: email,
            senha: senhaMD5,
            tipo_usuario: tipo_usuarioInt
        };
    
        $.ajax({
            url: `http://${IP}:${PORT}/usuarios`,
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            data: JSON.stringify(novoUsuario),
            success: function (response) {
                alert(JSON.stringify(response));
            },
            error: function (error) {
                const errorObject = JSON.parse(error.responseText);
                alert(JSON.stringify(errorObject));
            }
        });
    }

    // Função para cadastrar ponto
    function cadastrarPonto() {
        let nome;

        while(!nome || !nome.trim()){
            nome = prompt('Digite o nome do ponto');
            if(!nome || !nome.trim()){
                alert("Insira um NOME válido!")
            }
        }
        
        {
            $.ajax({
                url: `http://${IP}:${PORT}/pontos`,
                type: 'POST',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                data: JSON.stringify({ nome }),
                success: function (response) {
                    alert(JSON.stringify(response));
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
        }
    }

    function listarPontos() {
        let table = document.getElementById('tablePontos');
        var tbody;
    
        if (!table) {
            // Cria a tabela se não existir
            table = document.createElement('table');
            table.id = 'tablePontos';
            document.body.appendChild(table);
    
            // Cria o corpo da tabela
            tbody = document.createElement('tbody');
            table.appendChild(tbody);
        } else {
            // Se a tabela já existe, obtém o corpo existente
            tbody = table.querySelector('tbody');
    
            // Verifica se tbody existe antes de limpar seu conteúdo
            if (tbody) {    
                // Limpa o conteúdo do corpo da tabela
                while (tbody.firstChild) {
                    tbody.removeChild(tbody.firstChild);
                }
            } else {
                // Se tbody não existe, cria um novo elemento tbody
                tbody = document.createElement('tbody');
                table.appendChild(tbody);
            }
        }
    
        if (!tableVisible) {
            $.ajax({
                url: `http://${IP}:${PORT}/pontos`,
                type: 'GET',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                success: function (response) {
                    console.log(response);
                    if (response && response.pontos && response.pontos.length > 0) {
                        const pontos = response.pontos;
    
                        // Preenche o corpo da tabela
                        for (let i = 0; i < pontos.length; i++) {
                            const ponto = pontos[i];
                            
                            // Dentro da lógica que preenche o corpo da tabela
                            const row = tbody.insertRow(i);
    
                            const cell1 = row.insertCell(0);
                            cell1.innerHTML = ponto.nome;
    
                            const cell2 = row.insertCell(1);
                            cell2.innerHTML = ponto.ponto_id;
    
                            // Célula 3: Botões de Ação
                            const cell3 = row.insertCell(2);
    
                            // Adiciona botão de Atualizar
                            const btnAtualizar = document.createElement('button');
                            btnAtualizar.innerHTML = 'Atualizar';
                            btnAtualizar.onclick = function() {
                                atualizarPonto(ponto.ponto_id); // Chama a função de atualizar com o ID do ponto
                            };
                            cell3.appendChild(btnAtualizar);
    
                            // Adiciona botão de Excluir
                            const btnExcluir = document.createElement('button');
                            btnExcluir.innerHTML = 'Excluir';
                            btnExcluir.onclick = function() {
                                excluirPonto(ponto.ponto_id); // Chama a função de excluir com o ID do ponto
                            };
                            cell3.appendChild(btnExcluir);
                        }
    
                        toggleTable('tablePontos', true); // Mostra a tabela de pontos
                    } else {
                        alert("Nenhum ponto encontrado.");
                    }
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
        } else {
            clearTabela2(); // Limpa a tabela antes de ocultar
            tableVisible = false; // Define a tabela como oculta
        
            // Certifique-se de que a tabela e o tbody ainda existem
            const table = document.getElementById('tablePontos');
            const tbody = table ? table.querySelector('tbody') : null;
        
            if (tbody) {
                toggleTable('tablePontos', false); // Esconde a tabela de pontos
            } else {
                // Lógica para lidar com o caso em que tbody não é encontrado
                console.log("Tbody não encontrado.");
            }
        }
    }

    // Função para obter detalhes de um ponto específico
    function obterPonto() {
        let pontoId; 

        while(!pontoId || !pontoId.trim()){
            pontoId = prompt("Digite o ID do ponto:");
            if(!pontoId || !pontoId.trim()){
                alert("Insira um ID válido!")
            }
        }

        {
            $.ajax({
                url: `http://${IP}:${PORT}/pontos/${pontoId}`,
                type: 'GET',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                success: function (response) {
                    let ponto;
                    console.log(response);
                    if (response && response.ponto || response.pontos) {
                        if (response && response.ponto) {
                            ponto = response.ponto;
                        } else if (response && response.pontos) {
                            ponto = response.pontos;
                        }
    
                        clearTabela();
    
                        let table = document.getElementById('tablePontos');
                        if (!table) {
                            table = document.createElement('table');
                            table.id = 'tablePontos';
                            document.body.appendChild(table);
                        }
    
                        const thead = table.createTHead();
                        const row = thead.insertRow();
    
                        // Cabeçalho 1: nome
                        const th1 = document.createElement('th');
                        th1.innerHTML = 'Nome';
                        row.appendChild(th1);
    
                        // Cabeçalho 2: ponto_id
                        const th2 = document.createElement('th');
                        th2.innerHTML = 'ID do Ponto';
                        row.appendChild(th2);
    
                        const tableBody = document.createElement('tbody');
                        const newRow = tableBody.insertRow(0);
    
                        const cell1 = newRow.insertCell(0);
                        cell1.innerHTML = ponto.nome;
    
                        const cell2 = newRow.insertCell(1);
                        cell2.innerHTML = ponto.ponto_id;
    
                        // Célula 3: Botões de Ação
                        const cell3 = newRow.insertCell(2);

                        // Adiciona botão de Atualizar
                        const btnAtualizar = document.createElement('button');
                        btnAtualizar.innerHTML = 'Atualizar';
                        btnAtualizar.onclick = function() {
                            atualizarPonto(ponto.ponto_id); // Chama a função de atualizar com o ID do ponto
                        };
                        cell3.appendChild(btnAtualizar);

                        // Adiciona botão de Excluir
                        const btnExcluir = document.createElement('button');
                        btnExcluir.innerHTML = 'Excluir';
                        btnExcluir.onclick = function() {
                            excluirPonto(ponto.ponto_id); // Chama a função de excluir com o ID do ponto
                        };
                        cell3.appendChild(btnExcluir);
    
                        table.appendChild(tableBody);
                        toggleTable('tablePontos', true); // Mostra a tabela de pontos
                    } else {
                        alert("Ponto não encontrado.");
                    }
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
        }
    }

    function atualizarPonto(pontoId) {
        const novoNome = prompt("Digite o novo nome do ponto:");
        if (novoNome) {
            $.ajax({
                url: `http://${IP}:${PORT}/pontos/${pontoId}`,
                type: 'PUT',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                data: JSON.stringify({ nome: novoNome }),
                success: function (response) {
                    alert(JSON.stringify(response));
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
        }
    }
    
    function excluirPonto(pontoId) {
        $.ajax({
            url: `http://${IP}:${PORT}/pontos/${pontoId}`,
            type: 'DELETE',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            success: function (response) {
                alert(JSON.stringify(response));
            },
            error: function (error) {
                const errorObject = JSON.parse(error.responseText);
                alert(JSON.stringify(errorObject));
            }
        });
    }

    // Função para criar um novo segmento
    function criarSegmento() {
        let ponto_inicial;
        while(!ponto_inicial || !ponto_inicial.trim()){
            ponto_inicial = prompt('Informe o ponto_inicial para o segmento:');
            if(!ponto_inicial || !ponto_inicial.trim()){
                alert("Insira um ponto_inicial válido!")
            }
        }

        let ponto_final;
        while(!ponto_final || !ponto_final.trim()){
            ponto_final = prompt('Informe o ponto_final para o segmento:');
            if(!ponto_final || !ponto_final.trim()){
                alert("Insira um ponto_final válido!")
            }
        }

        let distancia;
        while (distancia === undefined || distancia === null) {
            const userInput = prompt('Informe a distância do Segmento:');

            if (userInput === null) {
                // O usuário pressionou "Cancelar" no prompt
                alert("Operação cancelada");
                break;
            }

            distancia = parseFloat(userInput.replace(',', '.'));

            if (isNaN(distancia)) {
                alert("Insira uma distância válida!");
                distancia = undefined; // Define como undefined para continuar o loop
            }
        }
               
        let status;

        while (status !== 0 && status !== 1) {
            const userInput = prompt('Informe o status para o segmento: [0 ou 1]');

            if (userInput === null) {
                // O usuário pressionou "Cancelar" no prompt
                alert("Operação cancelada");
                break;
            }

            status = parseInt(userInput);

            if (isNaN(status) || (status !== 0 && status !== 1)) {
                alert("Insira um status válido (0 ou 1)!");
                status = undefined; // Define como undefined para continuar o loop
            }
        }

        let direcao;
        while(!direcao || !direcao.trim()){
            direcao = prompt('Informe o direcao para o segmento:');
            if(!direcao || !direcao.trim()){
                alert("Insira uma direcao válido!")
            }
        }

        const segmento = {
            distancia: distancia,
            ponto_inicial: ponto_inicial,
            ponto_final: ponto_final,
            status: status,
            direcao: direcao
        };

        $.ajax({
            url: `http://${IP}:${PORT}/segmentos`,
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            data: JSON.stringify(segmento),
            success: function (response) {
                alert(JSON.stringify(response));
            },
            error: function (error) {
                const errorObject = JSON.parse(error.responseText);
                alert(JSON.stringify(errorObject));
            }
        });
    }

    // Função para listar todos os segmentos
    function listarSegmentos() {
        if (!tableVisible) {
            $.ajax({
                url: `http://${IP}:${PORT}/segmentos`,
                type: 'GET',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                success: function (response) {
                    console.log(response);

                    let segmentos = response.segmentos;

                    clearTabela3(); // Limpa a tabela existente, se houver

                    let table = document.getElementById('tableSegmentos');
                    if (!table) {
                        table = document.createElement('table');
                        table.id = 'tableSegmentos';
                        document.body.appendChild(table);
                    }

                    const thead = table.createTHead();
                    const row = thead.insertRow();

                    // Cabeçalho 1: direcao
                    const th1 = document.createElement('th');
                    th1.innerHTML = 'Direção';
                    row.appendChild(th1);

                    // Cabeçalho 2: distancia
                    const th2 = document.createElement('th');
                    th2.innerHTML = 'Distância';
                    row.appendChild(th2);

                    // Cabeçalho 3: ponto_final
                    const th3 = document.createElement('th');
                    th3.innerHTML = 'Ponto Final';
                    row.appendChild(th3);

                    // Cabeçalho 4: ponto_inicial
                    const th4 = document.createElement('th');
                    th4.innerHTML = 'Ponto Inicial';
                    row.appendChild(th4);

                    // Cabeçalho 5: segmento_id
                    const th5 = document.createElement('th');
                    th5.innerHTML = 'ID do Segmento';
                    row.appendChild(th5);

                    // Cabeçalho 6: status
                    const th6 = document.createElement('th');
                    th6.innerHTML = 'Status';
                    row.appendChild(th6);

                    // Itera sobre os segmentos e adiciona linhas à tabela
                    for (let i = 0; i < segmentos.length; i++) {
                        const newRow = table.insertRow();
                        const cell1 = newRow.insertCell(0);
                        cell1.innerHTML = segmentos[i].direcao;

                        const cell2 = newRow.insertCell(1);
                        cell2.innerHTML = segmentos[i].distancia;

                        const cell3 = newRow.insertCell(2);
                        cell3.innerHTML = segmentos[i].ponto_final;

                        const cell4 = newRow.insertCell(3);
                        cell4.innerHTML = segmentos[i].ponto_inicial;

                        const cell5 = newRow.insertCell(4);
                        cell5.innerHTML = segmentos[i].segmento_id;

                        const cell6 = newRow.insertCell(5);
                        cell6.innerHTML = segmentos[i].status;
                        
                         // Adiciona célula para os botões de ação
                        const cellAcao = newRow.insertCell(6);

                        // Adiciona botão de Atualizar
                        const btnAtualizar = document.createElement('button');
                        btnAtualizar.innerHTML = 'Atualizar';
                        btnAtualizar.onclick = function () {
                            atualizarSegmento(segmentos[i].segmento_id); // Chama a função de atualizar com o ID do segmento
                        };
                        cellAcao.appendChild(btnAtualizar);

                        // Adiciona botão de Excluir
                        const btnExcluir = document.createElement('button');
                        btnExcluir.innerHTML = 'Excluir';
                        btnExcluir.onclick = function () {
                            excluirSegmento(segmentos[i].segmento_id); // Chama a função de excluir com o ID do segmento
                        };
                        cellAcao.appendChild(btnExcluir);
                    }

                    table.appendChild(thead);
                    toggleTable('tableSegmentos', true); // Mostra a tabela de segmentos
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
        } else {
            clearTabela3(); // Limpa a tabela antes de ocultar
            tableVisible = false; // Define a tabela como oculta
        
            // Certifique-se de que a tabela e o tbody ainda existem
            const table = document.getElementById('tablePontos');
            const tbody = table ? table.querySelector('tbody') : null;
        
            if (tbody) {
                toggleTable('tablePontos', false); // Esconde a tabela de pontos
            } 
        }
    }

    // Função para buscar segmento por ID
    function obterSegmento() {
        // Pede ao usuário que insira o ID do segmento
        let segmentoId;
        while (!segmentoId || !segmentoId.trim()) {
            segmentoId = prompt("Digite o ID do segmento:");
            if (!segmentoId || !segmentoId.trim()) {
                alert("Insira um ID válido!");
            }
        }

        // Realiza a chamada AJAX para obter o segmento com o ID fornecido
        $.ajax({
            url: `http://${IP}:${PORT}/segmentos/${segmentoId}`,
            type: 'GET',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            success: function (response) {
                console.log(response);

                // Limpa a tabela existente, se houver
                clearTabela3();

                // Verifica se a resposta contém um segmento
                if (response.segmento) {
                    const segmento = response.segmento;

                    let table = document.createElement('table');
                    table.id = 'tableSegmentos';
                    document.body.appendChild(table);

                    const thead = table.createTHead();
                    const row = thead.insertRow();

                    // Adiciona cabeçalhos à tabela
                    for (const key in segmento) {
                        if (segmento.hasOwnProperty(key)) {
                            const th = document.createElement('th');
                            th.innerHTML = key;
                            row.appendChild(th);
                        }
                    }

                    // Adiciona uma linha à tabela com os dados do segmento obtido
                    const newRow = table.insertRow();
                    for (const key in segmento) {
                        if (segmento.hasOwnProperty(key)) {
                            const cell = newRow.insertCell();
                            cell.innerHTML = segmento[key];
                        }
                    }

                      // Adiciona célula para os botões de ação
                      const cellAcao = newRow.insertCell(6);

                      // Adiciona botão de Atualizar
                      const btnAtualizar = document.createElement('button');
                      btnAtualizar.innerHTML = 'Atualizar';
                      btnAtualizar.onclick = function () {
                          atualizarSegmento(segmentoId); // Chama a função de atualizar com o ID do segmento
                      };
                      cellAcao.appendChild(btnAtualizar);

                      // Adiciona botão de Excluir
                      const btnExcluir = document.createElement('button');
                      btnExcluir.innerHTML = 'Excluir';
                      btnExcluir.onclick = function () {
                          excluirSegmento(segmentoId); // Chama a função de excluir com o ID do segmento
                      };
                      cellAcao.appendChild(btnExcluir);

                    table.appendChild(thead);
                    toggleTable('tableSegmentos', true); // Mostra a tabela de segmentos
                } else {
                    alert('Segmento não encontrado');
                }
            },
            error: function (error) {
                const errorObject = JSON.parse(error.responseText);
                alert(JSON.stringify(errorObject));
            }
        });
    }

    // Função para atualizar um segmento específico
    function atualizarSegmento(segmentoId) {    
        let ponto_inicial;
        while(!ponto_inicial || !ponto_inicial.trim()){
            ponto_inicial = prompt('Informe o ponto_inicial para atualizar o segmento:');
            if(!ponto_inicial || !ponto_inicial.trim()){
                alert("Insira um ponto_inicial válido!")
            }
        }

        let ponto_final;
        while(!ponto_final || !ponto_final.trim()){
            ponto_final = prompt('Informe o ponto_final para atualizar o segmento:');
            if(!ponto_final || !ponto_final.trim()){
                alert("Insira um ponto_final válido!")
            }
        }

        let distancia;
        while (distancia === undefined || distancia === null) {
            const userInput = prompt('Informe a distância atualizada do Segmento:');

            if (userInput === null) {
                // O usuário pressionou "Cancelar" no prompt
                alert("Operação cancelada");
                break;
            }

            distancia = parseFloat(userInput.replace(',', '.'));

            if (isNaN(distancia)) {
                alert("Insira uma distância válida!");
                distancia = undefined; // Define como undefined para continuar o loop
            }
        }
               
        let status;

        while (status !== 0 && status !== 1) {
            const userInput = prompt('Informe o novo status para o segmento: [0 ou 1]');

            if (userInput === null) {
                // O usuário pressionou "Cancelar" no prompt
                alert("Operação cancelada");
                break;
            }

            status = parseInt(userInput);

            if (isNaN(status) || (status !== 0 && status !== 1)) {
                alert("Insira um status válido (0 ou 1)!");
                status = undefined; // Define como undefined para continuar o loop
            }
        }

        let direcao;
        while(!direcao || !direcao.trim()){
            direcao = prompt('Informe o direcao para o segmento:');
            if(!direcao || !direcao.trim()){
                alert("Insira uma direcao válido!")
            }
        }

        const dadosAtualizados = {
            distancia: distancia,
            ponto_inicial: ponto_inicial,
            ponto_final: ponto_final,
            status: status,
            direcao: direcao
        };


            $.ajax({
                url: `http://${IP}:${PORT}/segmentos/${segmentoId}`,
                type: 'PUT',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                data: JSON.stringify(dadosAtualizados),
                success: function (response) {
                    alert(JSON.stringify(response));
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
    }
    
    // Função para excluir um segmento específico
    function excluirSegmento(segmentoId) {    
            $.ajax({
                url: `http://${IP}:${PORT}/segmentos/${segmentoId}`,
                type: 'DELETE',
                contentType: 'application/json',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                success: function (response) {
                    alert(JSON.stringify(response));
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(JSON.stringify(errorObject));
                }
            });
    }
    
