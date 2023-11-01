let IP = localStorage.getItem('IP');
let PORT = localStorage.getItem('PORT');
let token = localStorage.getItem('token');

    if (token) {
        $('#options').css('display', 'block');
        $('#loginForm').css('display', 'none');
    }

    function solicitarIDUsuario() {
        const id = prompt('Digite o ID do usuário:');
        if (id) {
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
                    registro: registro,
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
                $('#options').css('display', 'none');
                $('#loginForm').css('display', 'block');
            },
            error: function (error) {
                const errorObject = JSON.parse(error.responseText);
                alert(error);
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
            console.error(error);
        }
    });
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
                    console.log(response);
                    if (response && response.usuario) {
                        const usuario = response.usuario;

                        // Limpa a tabela antes de adicionar o usuário por ID
                        clearTable();

                        table = document.getElementById('tableUsuarios');
                        if (!table) {
                            table = document.createElement('table');
                            table.id = 'tableUsuarios';
                            document.body.appendChild(table);
                        }

                        const tableBody = document.createElement('tbody');
                        const row = tableBody.insertRow(0);

                        const cell1 = row.insertCell(0);
                        cell1.innerHTML = usuario.nome;

                        const cell2 = row.insertCell(1);
                        cell2.innerHTML = usuario.registro;

                        const cell3 = row.insertCell(2);
                        cell3.innerHTML = usuario.email;

                        const cell4 = row.insertCell(3);
                        cell4.innerHTML = usuario.tipo_usuario === 1 ? 'Administrador' : 'Usuário Comum';

                        table.appendChild(tableBody);
                        toggleTable(true); // Sempre mostra a tabela quando um usuário é listado
                    } else {
                        alert("Usuário não encontrado.");
                    }
                },
                error: function (error) {
                    if (error.status === 401) {
                        alert("Precisa ser administrador para realizar esta ação.");
                    } else {
                        console.error(error);
                    }
                }
            });
        } else {
            alert("Faça login para executar esta ação.");
        }
    }

    function criarUsuario() {
        const nome = prompt('Digite o nome do usuário:');
        const registro = prompt('Digite o registro do usuário:');
        const email = prompt('Digite o e-mail do usuário:');
        const senha = prompt('Digite a senha do usuário:');
        const tipo_usuario = prompt('Digite o tipo de usuário (1 para administrador, 0 para usuário comum):');

        const senhaMD5 = md5(senha);

        const novoUsuario = {
            nome: nome,
            registro: registro,
            email: email,
            senha: senhaMD5,
            tipo_usuario: parseInt(tipo_usuario)
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
                alert(JSON.stringify(error));
            }

        });
    }
