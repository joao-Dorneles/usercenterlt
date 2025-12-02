import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import smtplib
from flask import jsonify
import requests
import socket

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

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME", "noreply@isso-nao-deve-ser-usado.com"))

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

    subject = "Redefinição de Senha"
    body = f"""Olá {user.nome or ''},

    Para redefinir sua senha, clique no link abaixo:
    {reset_url}

    Se você não solicitou, ignore este e-mail.
    """
    try:
        msg = Message(subject, recipients=[user.email])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"SMTP falhou. Tentando SendGrid. Erro: {e}")

    try:
        import requests
        sg_key = os.getenv("SENDGRID_API_KEY")
        if not sg_key:
            return False
        
        data = {
            "personalizations": [{"to": [{"email": user.email}]}],
            "from": {"email": os.getenv("MAIL_DEFAULT_SENDER")},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}]
        }

        r = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=data,
            headers={"Authorization": f"Bearer {sg_key}"}
        )

        return r.status_code in (200, 202)

    except Exception as e:
        app.logger.error(f"SendGrid falhou também: {e}")
        return False
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            next_url = request.url
            flash("Você precisa fazer login para acessar esta página.", "warning")
            return redirect(url_for('index', next=next_url))
        return f(*args, **kwargs)
    return decorated_function    

#pra que tantos codigos...
#se a vida não é programada...
#e as melhores coisas não tem logica?

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
            ok = email_recuperar(user)
            if ok:
                flash("Um e-mail foi enviado com instruções para redefinir sua senha.", "info")
            else:
                flash("Falha ao enviar o e-mail de recuperação. Tente novamente mais tarde.", "danger")
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

@app.route("/test-smtp")
def test_smtp():
    server = app.config.get("MAIL_SERVER")
    port = int(app.config.get("MAIL_PORT", 0) or 0)
    use_ssl = bool(app.config.get("MAIL_USE_SSL"))
    use_tls = bool(app.config.get("MAIL_USE_TLS"))
    user = app.config.get("MAIL_USERNAME")

    try:
        if use_ssl or port == 465:
            s = smtplib.SMTP_SSL(server, port, timeout=10)
        else:
            s = smtplib.SMTP(server, port, timeout=10)
            if use_tls or port == 587:
                s.starttls()
        if user:
            s.login(user, app.config.get("MAIL_PASSWORD"))
        s.quit()
        return jsonify({"ok": True, "msg": "SMTP OK", "server": server, "port": port, "ssl": use_ssl, "tls": use_tls})
    except Exception as e:
        app.logger.exception("SMTP test failed")
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv("FLASK_ENV", "development") != "production"
    app.run(debug=debug_mode)
