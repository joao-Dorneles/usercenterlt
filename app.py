from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/cadastro")
def cadastro():
    return render_template("cadastro.html")

@app.route("/hubjogos")
def cadastro():
    return render_template("hubjogos.html")

if __name__ == "__main__":
    app.run(debug=True)