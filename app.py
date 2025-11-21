from flask import Flask, render_template

app = Flask(__name__)

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

@app.route("/conta")
def conta():
    return render_template("conta.html")

if __name__ == "__main__":
    app.run(debug=True)