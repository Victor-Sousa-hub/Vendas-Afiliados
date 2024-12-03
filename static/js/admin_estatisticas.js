fetch('/api/admin')
    .then(response => response.json())
    .then(usuarios => {
        const tabelaUsuarios = document.getElementById("tabelaUsuarios");

        usuarios.forEach(user => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${user.id}</td>
                <td>${user.nome}</td>
                <td>${user.email}</td>
                <td>${user.status}</td>
                <td>R$ ${user.total_gasto.toFixed(2)}</td>
                <td>
                    <button onclick="bloquearUsuario(${user.id})">Bloquear</button>
                    <button onclick="excluirUsuario(${user.id})">Excluir</button>
                </td>
            `;

            tabelaUsuarios.appendChild(row);
        });
    })
    .catch(error => console.error('Erro ao carregar os usuários:', error));
