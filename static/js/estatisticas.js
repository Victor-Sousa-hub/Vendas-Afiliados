document.addEventListener("DOMContentLoaded", function () {
    fetch("/api/indicacoes") // Faz a requisição à API
        .then((response) => response.json())
        .then((indicacoes) => {
            const tabela = document.getElementById("tabelaIndicacoes");

            indicacoes.forEach((indicacao, index) => {
                const linha = document.createElement("tr");
                linha.innerHTML = `
                    <td>${indicacao.nome}</td>
                    <td>${indicacao.email}</td>
                    <td>${indicacao.convidados.length}</td>
                    <td>R$ ${indicacao.comissoes.toFixed(2)}</td>
                    <td>
                        <button class="toggle-btn" data-index="${index}">Ver Convidados</button>
                    </td>
                `;
                tabela.appendChild(linha);

                const detalhes = document.createElement("tr");
                detalhes.classList.add("detalhes");
                detalhes.style.display = "none";
                detalhes.innerHTML = `
                    <td colspan="5">
                        <table class="tabela-subindicacoes">
                            <thead>
                                <tr>
                                    <th>Nome</th>
                                    <th>E-mail</th>
                                    <th>Comissões</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${indicacao.convidados
                                    .map(
                                        (convidado) => `
                                    <tr>
                                        <td>${convidado.nome}</td>
                                        <td>${convidado.email}</td>
                                        <td>R$ ${convidado.comissoes.toFixed(2)}</td>
                                    </tr>
                                `
                                    )
                                    .join("")}
                            </tbody>
                        </table>
                    </td>
                `;
                tabela.appendChild(detalhes);

                linha.querySelector(".toggle-btn").addEventListener("click", function () {
                    if (detalhes.style.display === "none") {
                        detalhes.style.display = "table-row";
                        this.textContent = "Esconder Convidados";
                    } else {
                        detalhes.style.display = "none";
                        this.textContent = "Ver Convidados";
                    }
                });
            });
        })
        .catch((error) => {
            console.error("Erro ao carregar as indicações:", error);
        });
});
