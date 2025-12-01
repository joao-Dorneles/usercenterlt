import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import IntegrityError

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
        email = request.form['email']
        senha = request.form['senha']
        cpf = request.form['cpf']

        novo_usuario = usuarios(nome=nome, email=email, cpf=cpf)
        novo_usuario.set_senha(senha)
        db.session.add(novo_usuario)
        db.session.commit()
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
    return render_template("conta.html")

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Você saiu da conta com sucesso.", "info")
    return redirect(url_for("index"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv("FLASK_ENV", "development") != "production"
    app.run(debug=debug_mode)
