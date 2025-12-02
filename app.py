import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer


load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-secret-if-missing")

database_url = os.getenv("DATABASE_URL")
if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_recycle": 1800,}
db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False 
app.config['MAIL_USE_SSL'] = True  
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_DEBUG'] = True
mail = Mail(app)

class usuarios(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    email = db.Column(db.String(150))
    cpf = db.Column(db.String(14))
    senha_hash = db.Column(db.String(255), nullable=False)

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha) 

    def check_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)
    
    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='recover-key')

    @staticmethod
    def verify_reset_token(token, max_age=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, salt='recover-key', max_age=max_age)
            user_id = data.get('user_id')
        except Exception as e:
            app.logger.debug(f"verify_reset_token failed: {e}")
            return None
        return usuarios.query.get(user_id)
    
def email_recuperar(user):
    token = user.get_reset_token()
    reset_url = url_for('reset_token', token=token, _external=True)

    msg = Message('Redefinição de Senha', recipients=[user.email])
    msg.body = f"""Olá {user.nome or ''},

Para redefinir sua senha, clique no link abaixo:
{reset_url}

Se você não solicitou, ignore este e-mail. O link expira em 30 minutos (ou conforme configurado).
"""
    try:
        app.logger.debug(f"Enviando e-mail de recuperação para {user.email} (reset_url={reset_url})")
        mail.send(msg)
        app.logger.info(f"E-mail de recuperação enviado para: {user.email}")
    except Exception as e:
        app.logger.exception("ERRO AO ENVIAR E-MAIL:")
        flash("Falha ao enviar e-mail de redefinição. Tente novamente mais tarde.", "danger")
        raise 
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            next_url = request.url
            flash("Você precisa fazer login para acessar esta página.", "warning")
            return redirect(url_for('index', next=next_url))
        return f(*args, **kwargs)
    return decorated_function    

@app.route("/", methods=['GET', 'POST'])
def index():
    next_url = request.args.get('next', url_for('conta'))
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        senha = request.form['senha']

        user = usuarios.query.filter_by(email=email).first()
        if user and user.check_senha(senha):
            session['user_id'] = user.id
            flash('Logado com sucesso!', 'success')
            return redirect(next_url or url_for('conta'))
        
        flash('Credenciais inválidas. Tente novamente.', 'danger')
        return render_template("index.html", next=next_url)
    return render_template("index.html")

@app.route("/cadastro", methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email'].strip().lower()
        senha = request.form['senha']
        cpf = request.form['cpf']

        novo_usuario = usuarios(nome=nome, email=email, cpf=cpf)
        novo_usuario.set_senha(senha)
        db.session.add(novo_usuario)
        try:
            db.session.commit()
            flash("Cadastro realizado com sucesso! Faça login.", "success")
            return redirect(url_for('index'))
        except IntegrityError:
            db.session.rollback()
            flash("Erro: Email ou CPF já cadastrado.", "danger")
            return render_template("cadastro.html")
    return render_template("cadastro.html")

@app.route("/hubjogos")
@login_required
def hubjogos():
    return render_template("hubjogos.html")

@app.route("/deliverydash")
def deliverydash():
    return render_template("deliverydash.html")

@app.route("/snake")
def snake():
    return render_template("snake.html")

@app.route("/conta")
@login_required
def conta():
    user_id = session.get('user_id')
    user = usuarios.query.get_or_404(user_id)
    return render_template("conta.html", user=user)

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Você saiu da conta com sucesso.", "info")
    return redirect(url_for("index"))

@app.route("/recuperar", methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = usuarios.query.filter_by(email=email).first()
        if user:
            try:
                email_recuperar(user) 
                flash("Um e-mail foi enviado com instruções para redefinir sua senha.", "info")
            except Exception as e:
                print(f"ERRO DE ENVIO DE E-MAIL (GERAL): {e}") 
                flash("Falha interna ao enviar e-mail. Verifique suas credenciais no .env.", "danger")
            return redirect(url_for('index'))
        else:
            flash("Se a sua conta existir, um e-mail com instruções foi enviado.", "warning")
            return redirect(url_for('index'))
            
    return render_template("recuperar.html")

@app.route("/reset_senha/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = usuarios.verify_reset_token(token)
    if user is None:
        flash("Token inválido ou expirado.", "warning")
        return redirect(url_for('recuperar'))
    
    if request.method == 'POST':
        nova_senha = request.form['nova_senha'] 

        try:
            user.set_senha(nova_senha)
            db.session.commit()
            
            flash("Sua senha foi atualizada com sucesso!", "success")
            return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback() 
            print("-" * 50)
            print(f"ERRO FATAL AO SALVAR SENHA NO BD: {e}") 
            print("-" * 50)
            flash("Ocorreu um erro ao atualizar a senha. Tente novamente mais tarde.", "danger")
            return render_template('redefinir.html', token=token) 
    return render_template('redefinir.html', token=token)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv("FLASK_ENV", "development") != "production"
    app.run(debug=debug_mode)
