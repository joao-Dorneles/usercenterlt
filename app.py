import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer
from flask import jsonify
import requests
import socket
from sqlalchemy.sql.functions import coalesce
import re
from sqlalchemy.dialects.postgresql import MONEY

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

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin_padrao") 
ADMIN_PASSWORD_TEXT = os.getenv("ADMIN_PASSWORD", "senha_padrao_admin") 
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD_TEXT)

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'images', 'produtos')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
IMAGEM_PADRAO_PRODUTO = "notfound.jpeg"

class Produtos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=True)
    preco = db.Column(MONEY, nullable=False, default=0.00)
    categoria = db.Column(db.Text, nullable=False)
    imagem = db.Column(db.Text, nullable=False)
    

class usuarios(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    email = db.Column(db.String(150))
    cpf = db.Column(db.String(14))
    senha_hash = db.Column(db.String(255), nullable=False)
    score_jogo1 = db.Column(db.Integer, default=0)
    score_jogo2 = db.Column(db.Integer, default=0)
    total_score = db.Column(db.Integer, default=0)

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
    
def validar_email(email):
        padrao = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(padrao, email) is not None
    
def validar_nome(nome):
    padrao = r'^[A-Za-zÀ-ÿ ]+$'
    return re.match(padrao, nome) is not None

def validar_senha(senha):
    return len(senha) >= 6

def validar_cpf(cpf):
    """
    Valida CPF removendo as do js pontuação e aplicando
    a fórmula oficial dos dígitos verificadores.
    """
    cpf = re.sub(r'[^0-9]', '', cpf)

    if len(cpf) != 11:
        return False

    if cpf in (c * 11 for c in "0123456789"):
        return False

        #Cálculo do primeiro dígito verificador
    soma = 0
    for i in range(9):
        soma += int(cpf[i]) * (10 - i)
    digito1 = (soma * 10) % 11
    digito1 = 0 if digito1 == 10 else digito1

    if digito1 != int(cpf[9]):
        return False

        # Cálculo do segundo dígito verificador
    soma = 0
    for i in range(10):
        soma += int(cpf[i]) * (11 - i)
    digito2 = (soma * 10) % 11
    digito2 = 0 if digito2 == 10 else digito2

    if digito2 != int(cpf[10]):
        return False
    return True

def email_recuperar(user):
    sg_key = os.getenv("SENDGRID_API_KEY")
    sender_email = os.getenv("MAIL_DEFAULT_SENDER", "noreply.linhadotempo@gmail.com") 
    
    if not sg_key:
        app.logger.error("SENDGRID_API_KEY não configurada. Falha no envio.")
        return False
        
    token = user.get_reset_token()
    reset_url = url_for('reset_token', token=token, _external=True)

    subject = "Redefinição de Senha"
    body = f"""Olá {user.nome or ''},

Para redefinir sua senha, clique no link abaixo:
{reset_url}

Se você não solicitou, ignore este e-mail.
"""
    try:
        data = {
            "personalizations": [{"to": [{"email": user.email}]}],
            "from": {"email": sender_email},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}]
        }

        r = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=data,
            headers={"Authorization": f"Bearer {sg_key}"}
        )

        if r.status_code in (200, 202):
            return True
        else:
            app.logger.error(f"SendGrid API Error {r.status_code}: {r.text[:200]}")
            return False

    except Exception as e:
        app.logger.error(f"SendGrid falhou totalmente (erro de rede/conexão): {e}")
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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash("Acesso restrito. Faça login como administrador.", "danger")
            return redirect(url_for('loginAdmin'))
        return f(*args, **kwargs)
    return decorated_function

#pra que tantos codigos...
#se a vida não é programada...
#e as melhores coisas não tem logica?

@app.route("/admin/produtos/adicionar", methods=['POST'])
@admin_required
def adicionar_produto():
    nome = request.form.get('nome')
    descricao = request.form.get('descricao')
    categoria = request.form.get('categoria')
    
    try:
        preco = float(request.form.get('preco', 0).replace(',', '.'))
    except ValueError:
        flash("Preço inválido.", "danger")
        return redirect(url_for('administradores'))

    imagem_url = IMAGEM_PADRAO_PRODUTO

    if 'imagem_upload' in request.files:
        file = request.files['imagem_upload']
        
        if file and allowed_file(file.filename):
            filename = file.filename 
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(file_path)
                imagem_url = '/static/images/produtos/' + filename
            except Exception as e:
                flash(f"Erro ao salvar a imagem: {e}", "danger")
                
    if not nome or preco <= 0 or not categoria:
        flash("Nome, Preço válido e Categoria são campos obrigatórios.", "danger")
        return redirect(url_for('administradores'))

    novo_produto = Produtos(nome=nome, descricao=descricao, preco=preco, categoria=categoria, imagem=imagem_url)
    db.session.add(novo_produto)
    db.session.commit()
    flash(f"Produto '{nome}' adicionado com sucesso!", "success")
    return redirect(url_for('administradores'))

@app.route("/admin/produtos/editar/<int:produto_id>", methods=['POST'])
@admin_required
def editar_produto(produto_id):
    produto = Produtos.query.get_or_404(produto_id)
    
    nome = request.form.get('nome')
    descricao = request.form.get('descricao')
    categoria = request.form.get('categoria')
    
    try:
        preco = float(request.form.get('preco', produto.preco).replace(',', '.'))
    except ValueError:
        flash("Preço inválido na edição.", "danger")
        return redirect(url_for('administradores'))
    
    if 'imagem_upload' in request.files:
        file = request.files['imagem_upload']
        
        if file and allowed_file(file.filename):
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
                produto.imagem = '/static/images/produtos/' + filename
            except Exception as e:
                flash(f"Erro ao salvar nova imagem: {e}", "danger")

    if not nome or preco <= 0 or not categoria:
        flash("Nome, Preço válido e Categoria são campos obrigatórios na edição.", "danger")
        return redirect(url_for('administradores'))

    produto.nome = nome
    produto.descricao = descricao
    produto.preco = preco
    produto.categoria = categoria
    
    db.session.commit()
    flash(f"Produto '{produto.nome}' atualizado com sucesso!", "success")
    return redirect(url_for('administradores'))

@app.route("/admin/produtos/remover/<int:produto_id>", methods=['POST'])
@admin_required
def remover_produto(produto_id):
    produto = Produtos.query.get_or_404(produto_id)
    produto_nome = produto.nome
    
    db.session.delete(produto)
    db.session.commit()
    
    flash(f"Produto '{produto_nome}' removido com sucesso!", "info")
    return redirect(url_for('administradores'))

@app.route("/loginAdmin", methods=['GET', 'POST'])
def loginAdmin():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        
        if usuario != ADMIN_USERNAME:
            flash("Credenciais de administrador inválidas.", "danger")
            return render_template("loginAdmin.html")

        if check_password_hash(ADMIN_PASSWORD_HASH, senha):
            session['admin_logged_in'] = True
            flash("Login de Administrador realizado com sucesso!", "success")
            return redirect(url_for('administradores'))
        else:
            flash("Credenciais de administrador inválidas.", "danger")
            return render_template("loginAdmin.html")
            
    return render_template("loginAdmin.html")

@app.route("/administradores")
@admin_required 
def administradores(): 
    ranking_data = usuarios.query.order_by(
        coalesce(usuarios.total_score, 0).desc() 
    ).all()

    produtos = Produtos.query.order_by(Produtos.id.asc()).all()
    return render_template("administradores.html", ranking_data=ranking_data, produtos=produtos, IMAGEM_PADRAO_PRODUTO=IMAGEM_PADRAO_PRODUTO)

@app.route("/logoutAdmin")
def logoutAdmin():
    session.pop('admin_logged_in', None)
    flash("Sessão de Administrador encerrada.", "info")
    return redirect(url_for('loginAdmin'))

@app.route("/", methods=['GET', 'POST'])
def index():
    next_url = request.args.get('next', url_for('hubjogos')) #fallback temporario
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        senha = request.form['senha']

        user = usuarios.query.filter_by(email=email).first()
        if user and user.check_senha(senha):
            session['user_id'] = user.id
            flash('Logado com sucesso!', 'success')
            return redirect(next_url or url_for('hubjogos')) #fallback temporario
        
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

        if not validar_nome(nome):
            flash("Nome inválido. Use apenas letras.", "danger")
            return render_template("cadastro.html")

        if not validar_email(email):
            flash("Email inválido.", "danger")
            return render_template("cadastro.html")

        if not validar_senha(senha):
            flash("A senha deve ter pelo menos 6 caracteres.", "danger")
            return render_template("cadastro.html")

        if not validar_cpf(cpf):
            flash("CPF inválido.", "danger")
            return render_template("cadastro.html")

        novo_usuario = usuarios(nome=nome[:15], email=email, cpf=cpf)
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
    user_logado_id = session.get('user_id')
    ranking_data = usuarios.query.order_by(
        coalesce(usuarios.total_score, 0).desc() 
    ).all()
    return render_template("hubjogos.html", ranking_data=ranking_data, user_logado_id=user_logado_id)

@app.route("/deliverydash")
@login_required
def deliverydash():
    user = usuarios.query.get(session["user_id"])
    initial_high_score = user.score_jogo1 or 0
    return render_template("deliverydash.html", initial_high_score=initial_high_score)

@app.route("/snake")
@login_required
def snake():
    user = usuarios.query.get(session["user_id"])
    initial_high_score = user.score_jogo2 or 0 
    
    return render_template("snake.html", initial_high_score=initial_high_score)

@app.route("/conta", methods=['GET', 'POST'])
@login_required
def conta():
    user_id = session.get('user_id')
    user = usuarios.query.get_or_404(user_id)
    if request.method == 'POST':    
        novo_nome = request.form.get('nome', user.nome).strip()
        novo_email = request.form.get('email', user.email).strip().lower()
        novo_cpf = request.form.get('cpf', user.cpf).strip()
    
        if not validar_nome(novo_nome):
            flash("Nickname inválido. Use apenas letras e números, max 15.", "danger")
            return redirect(url_for('conta'))

        if not validar_email(novo_email):
            flash("E-mail inválido. Verifique o formato.", "danger")
            return redirect(url_for('conta'))

        if not validar_cpf(novo_cpf):
            flash("CPF inválido. Verifique a formatação.", "danger")
            return redirect(url_for('conta'))
        
        if novo_email != user.email:
            email_check = usuarios.query.filter(usuarios.email == novo_email, usuarios.id != user_id).first()
            if email_check:
                flash("Este e-mail já está em uso por outra conta.", "danger")
                return redirect(url_for('conta'))

        if novo_cpf != user.cpf:
            cpf_check = usuarios.query.filter(usuarios.cpf == novo_cpf, usuarios.id != user_id).first()
            if cpf_check:
                flash("Este CPF já está cadastrado em outra conta.", "danger")
                return redirect(url_for('conta'))

        user.nome = novo_nome[:15]
        user.email = novo_email
        user.cpf = novo_cpf

        try:
            db.session.commit()
            flash("Seus dados foram atualizados com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            flash("Ocorreu um erro ao salvar as alterações. Tente novamente.", "danger")
        
            return redirect(url_for('conta'))
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
                flash("Um e-mail foi enviado com instruções para redefinir sua senha. VERIFIQUE A CAIXA DE SPAM", "info")
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

@app.route("/api/dash_score", methods=["POST"])
@login_required
def dash_score():
    """Rota para receber e salvar a pontuação do Delivery Dash."""
    data = request.get_json()
    novo_score = data.get("score", 0)

    try:
        novo_score = int(novo_score)
    except (TypeError, ValueError):
        return {"status": "error", "message": "Pontuação inválida"}, 400

    user = usuarios.query.get(session["user_id"])
    
    record_atual_jogo1 = user.score_jogo1 or 0
    record_atual_jogo2 = user.score_jogo2 or 0 
    
    saved_high_score = record_atual_jogo1
    
    if novo_score > record_atual_jogo1:
        user.score_jogo1 = novo_score
        saved_high_score = novo_score

        user.total_score = user.score_jogo1 + record_atual_jogo2
        
        db.session.commit() 
        return {
            "status": "ok", 
            "saved_high_score": user.score_jogo1,
            "total_score": user.total_score,
            "message": "Novo recorde do Jogo 1 e total score combinado atualizados."
        }
    
    return {
        "status": "ok", 
        "saved_high_score": saved_high_score,
        "total_score": user.total_score,
        "message": "Nova pontuação não é maior que o recorde. Total Score inalterado."
    }

@app.route("/api/snake_score", methods=["POST"])
@login_required
def snake_score():
    data = request.get_json()
    novo_score = data.get("score", 0)

    try:
        novo_score = int(novo_score)
    except (TypeError, ValueError):
        return {"status": "error", "message": "Pontuação inválida"}, 400

    user = usuarios.query.get(session["user_id"])

    record_atual_jogo2 = user.score_jogo2 or 0
    record_atual_jogo1 = user.score_jogo1 or 0
    
    saved_high_score = record_atual_jogo2

    if novo_score > record_atual_jogo2:
        user.score_jogo2 = novo_score
        saved_high_score = novo_score
        
        user.total_score = user.score_jogo2 + record_atual_jogo1
        
        db.session.commit()

        return {
            "status": "ok", 
            "saved_high_score": user.score_jogo2,
            "total_score": user.total_score,
            "message": "Novo recorde do Jogo 2 e total score combinado atualizados."
        }

    return {
        "status": "ok", 
        "saved_high_score": saved_high_score,
        "total_score": user.total_score,
        "message": "Nova pontuação não é maior que o recorde. Total Score inalterado."
    }


# essa rota é responsavel pela exclusao, ou seja, é critica [!]
@app.route("/excluir", methods=['POST'])
@login_required
def excluir_conta():
    user_id = session.get('user_id')
    user = usuarios.query.get(user_id) 

    if not user:
        flash("Erro: Usuário não encontrado.", "danger")
        return redirect(url_for('index'))

    try:
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None) 
        
        flash("Sua conta foi excluída com sucesso. Sentiremos sua falta!", "success")
        return redirect(url_for('index'))

    except Exception as e:
        db.session.rollback()
        print(f"ERRO AO EXCLUIR CONTA: {e}")
        flash("Ocorreu um erro ao excluir sua conta. Tente novamente.", "danger")
        return redirect(url_for('conta'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv("FLASK_ENV", "development") != "production"
    app.run(debug=debug_mode)
