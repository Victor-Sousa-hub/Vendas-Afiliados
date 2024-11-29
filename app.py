from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from urllib.parse import urlparse, urljoin
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import mercadopago
import os
from dotenv import load_dotenv
import uuid
from validate_docbr import CPF  # Biblioteca para validar CPFs
import random
from flask_session import Session


###########################################################################################
#                                   VARAIVEIS DE AMBIENTE                                 #
###########################################################################################
# Carrega as variáveis do .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

cpf_validator = CPF()

# Credenciais do Mercado Pago
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
sdk = mercadopago.SDK(ACCESS_TOKEN)

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))  # Valor padrão
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Configurações do Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'  # Pode ser alterado para 'redis' se Redis estiver configurado
app.config['SESSION_PERMANENT'] = False
Session(app)

mail = Mail(app)

###########################################################################################
#                                   FUNÇÕES AUXILIARES                                    #
###########################################################################################

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def generate_referral_link(user_id):
    base_url = "https://example.com/register"
    unique_code = uuid.uuid4().hex[:8]
    return f"{base_url}?ref={unique_code}"

def init_db():
    """Inicializa o banco de dados."""
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        referral_link TEXT UNIQUE,
        cpf TEXT UNIQUE NOT NULL,
        pagante INTERGET DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()
init_db()

def is_password_strong(password):
    """Verifica se a senha atende aos requisitos."""
    return (
        len(password) >= 8 and
        any(char.isdigit() for char in password) and
        any(char.islower() for char in password) and
        any(char.isupper() for char in password)
    )

# Modelo de Usuário
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

# Função para carregar usuário pelo ID
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], email=user[2])
    return None

###########################################################################################
#                                   ROTAS                                                 #
###########################################################################################

# Página inicial
@app.route('/')
def index():
    # Verifica se o usuário está logado
    if 'user_id' in session:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute('SELECT pagante FROM usuarios WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()

        # Se o usuário for pagante, redireciona para a área do cliente
        if user and user[0] == 1:
            return redirect(url_for('client_area'))

    # Caso contrário, renderiza a página inicial
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')  # Obtém o parâmetro `next` do URL
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password, pagante FROM usuarios WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Verifica a senha
            if check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['username'] = username
                flash('Login realizado com sucesso!', 'success')
                # Verifica se a URL de redirecionamento é segura
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)
                return redirect(url_for('client_area'))
            else:
                flash('Senha incorreta. Por favor, tente novamente.', 'danger')
        else:
            flash('Usuário não encontrado. Verifique os dados e tente novamente.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso.', 'success')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        cpf = request.form.get('cpf')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        # Verificar CPF
        if not cpf_validator.validate(cpf):
            flash('CPF inválido. Por favor, insira um CPF válido.', 'danger')
            return redirect(url_for('signup'))

        # Verificar senhas
        if password != confirm_password:
            flash('Senhas não coincidem. Tente novamente.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Geração do código de verificação
        verification_code = str(random.randint(100000, 999999))

        # Armazenar os dados no cache (session)
        session['pending_user'] = {
            'username': username,
            'email': email,
            'cpf': cpf,
            'password': hashed_password,
            'verification_code': verification_code
        }

        # Enviar o e-mail de verificação
        try:
            msg = Message('Código de Verificação - FIN20 Investimentos', recipients=[email])
            msg.body = f'Olá {username},\n\nSeu código de verificação é: {verification_code}\n\nUse este código para completar seu cadastro.'
            mail.send(msg)

            flash('Um código de verificação foi enviado para o seu e-mail.', 'success')
            return redirect(url_for('verify'))

        except Exception as e:
            flash(f'Erro ao enviar o e-mail: {e}', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form.get('code')
        pending_user = session.get('pending_user')

        if not pending_user:
            flash('Sessão expirada. Por favor, refaça o cadastro.', 'danger')
            return redirect(url_for('signup'))

        # Verificar o código de verificação
        if pending_user['verification_code'] != code:
            flash('Código inválido. Tente novamente.', 'danger')
            return redirect(url_for('verify'))

        try:
            conn = sqlite3.connect('usuarios.db')
            cursor = conn.cursor()

            # Salvar o usuário no banco definitivo
            cursor.execute(
                "INSERT INTO usuarios (username, email, password, referral_link, cpf) VALUES (?, ?, ?, ?, ?)",
                (
                    pending_user['username'],
                    pending_user['email'],
                    pending_user['password'],
                    f"https://example.com/register?ref={pending_user['username']}-{uuid.uuid4().hex[:8]}",
                    pending_user['cpf']
                )
            )
            conn.commit()
            conn.close()

            # Limpar o cache (session)
            session.pop('pending_user', None)

            flash('Cadastro concluído com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Erro ao salvar o usuário: {e}', 'danger')
            return redirect(url_for('verify'))

    return render_template('verify.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Verificar se o e-mail está registrado
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user:
            flash('E-mail não encontrado. Verifique e tente novamente.', 'danger')
            return redirect(url_for('forgot_password'))

        # Gerar código de verificação
        verification_code = str(random.randint(100000, 999999))
        session['password_reset'] = {
            'email': email,
            'verification_code': verification_code
        }

        # Enviar e-mail com o código
        try:
            msg = Message('Redefinição de Senha - FIN20 Investimentos', recipients=[email])
            msg.body = f'Olá,\n\nSeu código para redefinição de senha é: {verification_code}\n\nUse este código para continuar o processo.'
            mail.send(msg)

            flash('Um código de verificação foi enviado para o seu e-mail.', 'success')
            return redirect(url_for('verify_password_reset'))

        except Exception as e:
            flash(f'Erro ao enviar o e-mail: {e}', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/verify-password-reset', methods=['GET', 'POST'])
def verify_password_reset():
    if request.method == 'POST':
        code = request.form.get('code')
        reset_data = session.get('password_reset')

        if not reset_data:
            flash('Sessão expirada. Por favor, tente novamente.', 'danger')
            return redirect(url_for('forgot_password'))

        # Verificar se o código é válido
        if reset_data['verification_code'] != code:
            flash('Código inválido. Tente novamente.', 'danger')
            return redirect(url_for('verify_password_reset'))

        # Redirecionar para redefinir a senha
        flash('Código verificado com sucesso. Redefina sua senha.', 'success')
        return redirect(url_for('reset_password'))

    return render_template('verify_password_reset.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        reset_data = session.get('password_reset')

        if not reset_data:
            flash('Sessão expirada. Por favor, tente novamente.', 'danger')
            return redirect(url_for('forgot_password'))

        # Verificar se as senhas coincidem
        if password != confirm_password:
            flash('Senhas não coincidem. Tente novamente.', 'danger')
            return redirect(url_for('reset_password'))

        # Verificar força da senha
        if not is_password_strong(password):
            flash('A senha não cumpre os requisitos. Certifique-se de que tenha pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula e um número.', 'danger')
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Atualizar a senha no banco
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios SET password = ? WHERE email = ?", (hashed_password, reset_data['email']))
        conn.commit()
        conn.close()

        # Limpar sessão
        session.pop('password_reset', None)

        flash('Senha redefinida com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/checkout')
def checkout():
    # Verifica se o usuário está logado
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'danger')
        return redirect(url_for('login', next='/checkout'))

    # Renderiza a página de checkout se o usuário estiver logado
    return render_template('checkout.html', username=session['username'])

# Criar pagamento
@app.route('/payment', methods=['POST'])
def create_payment():
    # Dados do produto (esses podem vir do banco de dados)
    item = {
        "title": "Curso de Vendas Digitais",
        "description": "Curso completo para aprender vendas digitais",
        "quantity": 1,
        "unit_price": 20.0,
        "currency_id": "BRL"
    }

    # Preferências de pagamento
    preference_data = {
        "items": [item],
        "payer": {
            "name": request.form.get("name", "Cliente"),
            "email": request.form.get("email", "email@exemplo.com")
        },
        "back_urls": {
            "success": url_for('payment_success', _external=True),
            "failure": url_for('payment_failure', _external=True),
            "pending": url_for('payment_pending', _external=True)
        },
        "auto_return": "approved"
    }

    # Criar a preferência de pagamento
    preference_response = sdk.preference().create(preference_data)
    preference = preference_response["response"]

    # Redirecionar o cliente para a página de pagamento
    return redirect(preference["init_point"])

# Página de sucesso
@app.route('/payment/success')
def payment_success():
    if 'user_id' in session:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET pagante = 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        flash('Pagamento confirmado! Você agora tem acesso à área exclusiva.', 'success')
        return redirect(url_for('client_area'))
    else:
        flash('Faça login antes de realizar o pagamento.', 'danger')
        return redirect(url_for('login'))
    return render_template("success.html")

# Página de falha
@app.route('/payment/failure')
def payment_failure():
    return render_template("failure.html")

# Página de pagamento pendente
@app.route('/payment/pending')
def payment_pending():
    return render_template("pending.html")

@app.route('/client-area')
def client_area():
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'danger')
        return redirect(url_for('login', next='/client-area'))

    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute('SELECT pagante, username FROM usuarios WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash('Usuário não encontrado. Faça login novamente.', 'danger')
        session.clear()
        return redirect(url_for('login'))
    elif user[0] == 0:
        flash('Acesso negado. É necessário adquirir o produto.', 'warning')
        return redirect(url_for('checkout'))

    # Dados para a seção Investidor
    patrimonio = 10000  # Exemplo, substituir por dados reais do usuário
    historico_patrimonio = [8000, 8500, 9000, 9500, 10000]  # Exemplo

    ativos = [
        {'nome': 'Ativo A', 'quantidade': 10, 'valor_atual': 100, 'variacao': 5},
        {'nome': 'Ativo B', 'quantidade': 5, 'valor_atual': 200, 'variacao': -2},
    ]  # Exemplo

    # Dados para a seção Divulgador
    link_convite = f"http://seusite.com/cadastrar?ref={session['user_id']}"
    comissoes_recebidas = 500  # Exemplo, substituir por dados reais
    total_indicacoes = 25  # Exemplo
    desempenho_indicacoes = [5, 10, 15, 20, 25]  # Exemplo

    return render_template(
        'client_area.html',
        username=user[1],
        patrimonio=patrimonio,
        historico_patrimonio=historico_patrimonio,
        ativos=ativos,
        link_convite=link_convite,
        comissoes_recebidas=comissoes_recebidas,
        total_indicacoes=total_indicacoes,
        desempenho_indicacoes=desempenho_indicacoes
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8081,debug=True)
