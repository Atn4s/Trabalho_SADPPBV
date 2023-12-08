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
        if (id === null) {
            // O usuário pressionou "Cancelar" no prompt
            alert("Operação cancelada");
            return;
        }

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
                clearTabela2();
                clearTabela3();
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
        }
    }

    function addButtons(row, usuario) {
        const updateButton = document.createElement('button');
        updateButton.innerHTML = 'Atualizar';
        updateButton.onclick = function() {
            const novoNome = prompt('Digite o novo nome:', usuario.nome);
            if (novoNome === null){
                alert("Operação cancelada");
                return;
            }
            const novoEmail = prompt('Digite o novo email:', usuario.email);
            if (novoEmail === null){
                alert("Operação cancelada");
                return;
            }
            const novaSenha = prompt('Digite a nova senha:', usuario.senha);
            if (novaSenha === null){
                alert("Operação cancelada");
                return;
            }

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

        if (parseInt(registroGlobal) == parseInt(registroUsuarioASerExcluido)){
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
    
                const th1 = document.createElement('th');
                th1.innerHTML = 'Nome';
                row.appendChild(th1);
    
                const th2 = document.createElement('th');
                th2.innerHTML = 'Registro';
                row.appendChild(th2);
    
                const th3 = document.createElement('th');
                th3.innerHTML = 'Email';
                row.appendChild(th3);
    
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
    
                        const th1 = document.createElement('th');
                        th1.innerHTML = 'Nome';
                        row.appendChild(th1);
    
                        const th2 = document.createElement('th');
                        th2.innerHTML = 'Registro';
                        row.appendChild(th2);
    
                        const th3 = document.createElement('th');
                        th3.innerHTML = 'Email';
                        row.appendChild(th3);
    
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
            if (nome === null){
                alert("Operação cancelada");
                return;
            }
        }

        let registro;
        while(!registro || !registro.trim()){
            registro = prompt('Informe o REGISTRO para o usuário:');
            if (registro === null){
                alert("Operação cancelada");
                return;
            }
        }
        let registroInt = parseInt(registro, 10); // Converte para inteiro

        let email;
        while(!email || !email.trim()){
            email = prompt('Informe o EMAIL para o usuário:');
            if (email === null){
                alert("Operação cancelada");
                return;
            }
        }

        let senha;
        while(!senha || !senha.trim()){
            senha = prompt('Informe a SENHA para o usuário:');
            if (senha == null){
                alert("Operação cancelada");
                return;
            }
        }

        let tipo_usuario;
        while(tipo_usuario !== "0" && tipo_usuario !== "1"){
            tipo_usuario = prompt('Informe a TIPO DE USUÁRIO: [1 - ADMINISTRADOR] - [0 - COMUM]');
            if (tipo_usuario == null){
                alert("Operação cancelada");
                return;
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

    function cadastrarPonto() {
        let nome;
        while(!nome || !nome.trim()){
            nome = prompt('Digite o nome do ponto');
            if (nome == null){
                alert("Operação cancelada");
                return;
            }
        }
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

    function listarPontos() {
        let table = document.getElementById('tablePontos');
        var tbody;
    
        if (!table) {
            table = document.createElement('table');
            table.id = 'tablePontos';
            document.body.appendChild(table);
    
            tbody = document.createElement('tbody');
            table.appendChild(tbody);
        } else {
            tbody = table.querySelector('tbody');    
            if (tbody) {    
                while (tbody.firstChild) {
                    tbody.removeChild(tbody.firstChild);
                }
            } else {
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
    
                        for (let i = 0; i < pontos.length; i++) {
                            const ponto = pontos[i];
                            
                            const row = tbody.insertRow(i);
    
                            const cell1 = row.insertCell(0);
                            cell1.innerHTML = ponto.nome;
    
                            const cell2 = row.insertCell(1);
                            cell2.innerHTML = ponto.ponto_id;
    
                            const cell3 = row.insertCell(2);
    
                            const btnAtualizar = document.createElement('button');
                            btnAtualizar.innerHTML = 'Atualizar';
                            btnAtualizar.onclick = function() {
                                atualizarPonto(ponto.ponto_id); // Chama a função de atualizar com o ID do ponto
                            };
                            cell3.appendChild(btnAtualizar);
    
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
        
            const table = document.getElementById('tablePontos');
            const tbody = table ? table.querySelector('tbody') : null;
        
            if (tbody) {
                toggleTable('tablePontos', false); // Esconde a tabela de pontos
            } else {
                console.log("Tbody não encontrado.");
            }
        }
    }

    function obterPonto() {
        let pontoId; 

        while(!pontoId || !pontoId.trim()){
            pontoId = prompt("Digite o ID do ponto:");
            if (pontoId == null){
                alert("Operação cancelada");
                return;
            }
        }
        pontoId = parseInt(pontoId);
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

                    const th1 = document.createElement('th');
                    th1.innerHTML = 'Nome';
                    row.appendChild(th1);

                    const th2 = document.createElement('th');
                    th2.innerHTML = 'ID do Ponto';
                    row.appendChild(th2);

                    const tableBody = document.createElement('tbody');
                    const newRow = tableBody.insertRow(0);

                    const cell1 = newRow.insertCell(0);
                    cell1.innerHTML = ponto.nome;

                    const cell2 = newRow.insertCell(1);
                    cell2.innerHTML = ponto.ponto_id;

                    const cell3 = newRow.insertCell(2);

                    const btnAtualizar = document.createElement('button');
                    btnAtualizar.innerHTML = 'Atualizar';
                    btnAtualizar.onclick = function() {
                        atualizarPonto(ponto.ponto_id); // Chama a função de atualizar com o ID do ponto
                    };
                    cell3.appendChild(btnAtualizar);

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

    function atualizarPonto(pontoId) {
        const novoNome = prompt("Digite o novo nome do ponto:");
        if (novoNome == null){
            alert("Operação cancelada");
            return;
        }

        if (novoNome) {
            pontoId = parseInt(pontoId);

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
        pontoId = parseInt(pontoId);
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

    function criarSegmento() {
        let ponto_inicial;
        while(!ponto_inicial || !ponto_inicial.trim()){
            ponto_inicial = prompt('Informe o ponto_inicial para o segmento:');
            if (ponto_inicial == null){
                alert("Operação cancelada");
                return;
            }
        }
        ponto_inicial = parseInt(ponto_inicial);

        let ponto_final;
        while(!ponto_final || !ponto_final.trim()){
            ponto_final = prompt('Informe o ponto_final para o segmento:');
            if (ponto_final == null){
                alert("Operação cancelada");
                return;
            }
        }
        ponto_final = parseInt(ponto_final);

        let distancia;
        while (distancia === undefined || distancia === null) {
            const userInput = prompt('Informe a distância do Segmento:');
            if (userInput === null) {
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
            if (direcao == null){
                alert("Operação cancelada");
                return;
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

                    const th1 = document.createElement('th');
                    th1.innerHTML = 'Direção';
                    row.appendChild(th1);

                    const th2 = document.createElement('th');
                    th2.innerHTML = 'Distância';
                    row.appendChild(th2);

                    const th3 = document.createElement('th');
                    th3.innerHTML = 'Ponto Final';
                    row.appendChild(th3);

                    const th4 = document.createElement('th');
                    th4.innerHTML = 'Ponto Inicial';
                    row.appendChild(th4);

                    const th5 = document.createElement('th');
                    th5.innerHTML = 'ID do Segmento';
                    row.appendChild(th5);

                    const th6 = document.createElement('th');
                    th6.innerHTML = 'Status';
                    row.appendChild(th6);

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
                        
                        const cellAcao = newRow.insertCell(6);

                        const btnAtualizar = document.createElement('button');
                        btnAtualizar.innerHTML = 'Atualizar';
                        btnAtualizar.onclick = function () {
                            atualizarSegmento(segmentos[i].segmento_id); // Chama a função de atualizar com o ID do segmento
                        };
                        cellAcao.appendChild(btnAtualizar);
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
            const table = document.getElementById('tablePontos');
            const tbody = table ? table.querySelector('tbody') : null;
            if (tbody) {
                toggleTable('tablePontos', false); // Esconde a tabela de pontos
            } 
        }
    }

    function obterSegmento() {
        const tabelaExistente = document.getElementById('tableSegmentos');

        if (tabelaExistente) {
            tabelaExistente.remove();
            return;
        }
        let segmentoId;
        while (!segmentoId || !segmentoId.trim()) {
            segmentoId = prompt("Digite o ID do segmento:");
            if (segmentoId == null){
                alert("Operação cancelada");
                return;
            }
        }
        segmentoId = parseInt(segmentoId);
        $.ajax({
            url: `http://${IP}:${PORT}/segmentos/${segmentoId}`,
            type: 'GET',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            success: function (response) {
                console.log(response);
                clearTabela3();
                if (response.segmento) {
                    const segmento = response.segmento;

                    let table = document.createElement('table');
                    table.id = 'tableSegmentos';
                    document.body.appendChild(table);

                    const thead = table.createTHead();
                    const row = thead.insertRow();

                    for (const key in segmento) {
                        if (segmento.hasOwnProperty(key)) {
                            const th = document.createElement('th');
                            th.innerHTML = key;
                            row.appendChild(th);
                        }
                    }
                    const newRow = table.insertRow();
                    for (const key in segmento) {
                        if (segmento.hasOwnProperty(key)) {
                            const cell = newRow.insertCell();
                            cell.innerHTML = segmento[key];
                        }
                    }
                    const cellAcao = newRow.insertCell(6);

                    const btnAtualizar = document.createElement('button');
                    btnAtualizar.innerHTML = 'Atualizar';
                    btnAtualizar.onclick = function () {
                        atualizarSegmento(segmentoId); // Chama a função de atualizar com o ID do segmento
                    };
                    cellAcao.appendChild(btnAtualizar);

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

    function atualizarSegmento(segmentoId) {    
        let ponto_inicial;
        while(!ponto_inicial || !ponto_inicial.trim()){
            ponto_inicial = prompt('Informe o ponto_inicial para atualizar o segmento:');
            if (ponto_inicial == null){
                alert("Operação cancelada");
                return;
            }
        }
        ponto_inicial = parseInt(ponto_inicial);

        let ponto_final;
        while(!ponto_final || !ponto_final.trim()){
            ponto_final = prompt('Informe o ponto_final para atualizar o segmento:');
            if (ponto_final == null){
                alert("Operação cancelada");
                return;
            }
        }
        ponto_final = parseInt(ponto_final);

        let distancia;
        while (distancia === undefined || distancia === null) {
            const userInput = prompt('Informe a distância atualizada do Segmento:');
            if (userInput === null){
                alert("Operação cancelada");
                break;
            }
            distancia = parseFloat(userInput.replace(',', '.'));
            if (isNaN(distancia)){
                alert("Insira uma distância válida!");
                distancia = undefined; // Define como undefined para continuar o loop
            }
        }
               
        let status;
        while (status !== 0 && status !== 1) {
            const userInput = prompt('Informe o novo status para o segmento: [0 ou 1]');
            if (userInput === null){
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
            if (direcao == null){
                alert("Operação cancelada");
                return;
            }
        }

        const dadosAtualizados = {
            distancia: distancia,
            ponto_inicial: ponto_inicial,
            ponto_final: ponto_final,
            status: status,
            direcao: direcao
        };

        segmentoId = parseInt(segmentoId);
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
    
    function excluirSegmento(segmentoId) {    
        segmentoId = parseInt(segmentoId);
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

    function calcularrota() {    
        // Obtenha valores de origem e destino usando prompt
        const origem = prompt("Digite o ponto de origem:");
        const destino = prompt("Digite o ponto de destino:");
    
        // Certifique-se de que os valores não estão vazios ou são null antes de enviar a solicitação
        if (!origem || !destino) {
            alert("Por favor, preencha os campos de origem e destino.");
            return;
        }
        
        // Dados a serem enviados na solicitação
        const requestData = {
            origem: origem,
            destino: destino
        };
                
        $.ajax({
            url: `http://${IP}:${PORT}/rotas`,
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            data: JSON.stringify(requestData),
            success: function (response) {
                console.log(response);
                clearTabela3();
            
                const tableId = 'tableRotas';
                const existingTable = document.getElementById(tableId);
            
                if (existingTable) {
                    // Se a tabela já existe, remova-a para esconder
                    existingTable.parentNode.removeChild(existingTable);
                    toggleTable(tableId, false);
                }
            
                if (response.success && response.rota) {
                    const rotas = response.rota;
            
                    let table = document.createElement('table');
                    table.id = tableId;
                    document.body.appendChild(table);
            
                    const thead = table.createTHead();
                    const row = thead.insertRow();
            
                    const headers = ["#", "Ponto inicial do segmento", "Ponto final do segmento", "Distância (m)", "Direção"];
            
                    for (const headerText of headers) {
                        const th = document.createElement('th');
                        th.innerHTML = headerText;
                        row.appendChild(th);
                    }
            
                    for (let i = 0; i < rotas.length; i++) {
                        const rota = rotas[i];
                        const newRow = table.insertRow();
                        newRow.insertCell().innerHTML = i + 1; // Adiciona o número da linha
                        newRow.insertCell().innerHTML = rota.ponto_inicial;
                        newRow.insertCell().innerHTML = rota.ponto_final;
                        newRow.insertCell().innerHTML = rota.distancia;
                        newRow.insertCell().innerHTML = rota.direcao;
                        newRow.insertCell().innerHTML = (i === rotas.length - 1) ? "DESTINO" : ''; // Adiciona o destino à última linha
                    }
            
                    table.appendChild(thead);
                    toggleTable(tableId, true); // Mostra a tabela de rotas
                } else {
                    alert('Erro ao obter rota');
                }
            },
        });
    }
    