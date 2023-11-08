let IP = localStorage.getItem('IP');
let PORT = localStorage.getItem('PORT');
let token = localStorage.getItem('token');

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
                },
                error: function (error) {
                    const errorObject = JSON.parse(error.responseText);
                    alert(errorObject.message);                    
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

    function toggleTable(show) {
        table = document.getElementById('tableUsuarios');
        if (show) {
            table.style.display = 'block'; // Mostra a tabela
            tableVisible = true;
        } else {
            table.style.display = 'none'; // Esconde a tabela
            tableVisible = false;
        }
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
                }                
                
                table.appendChild(tableBody);
                toggleTable(true); // Sempre mostra a tabela quando os usuários são listados
            } else {
                console.error("Nenhum usuário encontrado.");
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
            toggleTable(false); // Esconde a tabela
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
    
                        table.appendChild(tableBody);
                        toggleTable(true);
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
    
