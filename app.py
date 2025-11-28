from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = 'X9f@3Qp!vT7#Lm2^dS5%hR8&kW1*Zc4$Nq6@yB0!uF3^Jt'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ltusers_user:CcXX7JTFb5SqLY6X0GLK10zKb1rw1YRw@dpg-d4kvp13uibrs73foq340-a.oregon-postgres.render.com/ltusers'

db = SQLAlchemy(app)
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/cadastro")
def cadastro():
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
    app.run(debug=True)