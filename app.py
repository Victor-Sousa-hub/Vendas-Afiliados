from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from urllib.parse import urlparse, urljoin
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import mercadopago
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Credenciais do Mercado Pago
ACCESS_TOKEN = "TEST-5112559051927979-112019-02af7291ec44479c4f7f7be054a4d7cd-1363319531"
sdk = mercadopago.SDK(ACCESS_TOKEN)

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc




# Banco de Dados
def init_db():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            pagante INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()

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

#\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-ROTAS-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\

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
        password = request.form.get('password')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            conn = sqlite3.connect('usuarios.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            conn.close()
            flash('Conta criada com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário ou e-mail já existente.', 'danger')

    return render_template('signup.html')

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
    cursor.execute('SELECT pagante FROM usuarios WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash('Usuário não encontrado. Faça login novamente.', 'danger')
        session.clear()
        return redirect(url_for('login'))
    elif user[0] == 0:
        flash('Acesso negado. É necessário adquirir o produto.', 'warning')
        return redirect(url_for('checkout'))

    return render_template('client_area.html', username=session['username'])

if __name__ == '__main__':
    app.run(debug=True)
