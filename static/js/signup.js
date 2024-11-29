// Alternar visibilidade da senha
function togglePasswordVisibility(toggleId, passwordId) {
    const toggle = document.getElementById(toggleId);
    const passwordField = document.getElementById(passwordId);

    toggle.addEventListener('click', () => {
        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            toggle.textContent = 'Ocultar';
        } else {
            passwordField.type = 'password';
            toggle.textContent = 'Mostrar';
        }
    });
}

// Validar força da senha
function validatePasswordStrength(password) {
    const length = document.getElementById('length');
    const uppercase = document.getElementById('uppercase');
    const lowercase = document.getElementById('lowercase');
    const number = document.getElementById('number');

    // Verifica cada critério
    if (password.length >= 8) {
        length.style.color = 'green';
    } else {
        length.style.color = 'red';
    }

    if (/[A-Z]/.test(password)) {
        uppercase.style.color = 'green';
    } else {
        uppercase.style.color = 'red';
    }

    if (/[a-z]/.test(password)) {
        lowercase.style.color = 'green';
    } else {
        lowercase.style.color = 'red';
    }

    if (/\d/.test(password)) {
        number.style.color = 'green';
    } else {
        number.style.color = 'red';
    }
}

// Adicionar eventos ao carregar a página
document.addEventListener('DOMContentLoaded', () => {
    // Alternar visibilidade das senhas
    togglePasswordVisibility('toggle-password', 'password');
    togglePasswordVisibility('toggle-confirm-password', 'confirm-password');

    // Validar força da senha enquanto o usuário digita
    const passwordField = document.getElementById('password');
    passwordField.addEventListener('input', (event) => {
        validatePasswordStrength(event.target.value);
    });
});
