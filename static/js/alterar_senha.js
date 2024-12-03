document.getElementById('alterarSenhaForm').addEventListener('submit', async function (event) {
    event.preventDefault(); // Evita o envio padrão do formulário

    // Obter os dados do formulário
    const senhaAtual = document.getElementById('senha-atual').value;
    const novaSenha = document.getElementById('nova-senha').value;
    const confirmarSenha = document.getElementById('confirmar-senha').value;

    // Enviar os dados para a API usando Fetch
    try {
        const response = await fetch('/api/alterar-senha', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                senha_atual: senhaAtual,
                nova_senha: novaSenha,
                confirmar_senha: confirmarSenha,
            }),
        });

        const result = await response.json();

        // Exibir mensagens na página
        const messages = document.getElementById('messages');
        messages.innerHTML = ''; // Limpa mensagens anteriores

        if (response.ok) {
            messages.innerHTML = `<div class="alert alert-success">${result.success}</div>`;
        } else {
            messages.innerHTML = `<div class="alert alert-danger">${result.error}</div>`;
        }
    } catch (error) {
        console.error('Erro ao processar a solicitação:', error);
        const messages = document.getElementById('messages');
        messages.innerHTML = `<div class="alert alert-danger">Erro ao tentar alterar a senha. Tente novamente mais tarde.</div>`;
    }
});
