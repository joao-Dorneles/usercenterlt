import os
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-secret-if-missing")

database_url = os.getenv("DATABASE_URL")
if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 1800 
}

db = SQLAlchemy(app)
#aha
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
@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        return "Boas vindas"
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
        return "Esta cadastrado"    
    return render_template("cadastro.html")

@app.route("/hubjogos")
def hubjogos():
    return render_template("hubjogos.html")

@app.route("/deliverydash")
def deliverydash():
    return render_template("deliverydash.html")

@app.route("/snake")
def snake():
    return render_template("snake.html")

@app.route("/conta")
def conta():
    return render_template("conta.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv("FLASK_ENV", "development") != "production"
    app.run(debug=debug_mode)
