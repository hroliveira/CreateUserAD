from flask import Flask, render_template, request, flash, redirect, url_for, session
from functools import wraps
from config import Config
from ad_logic import create_ad_user, authenticate_user
from logger_config import logger

app = Flask(__name__)
app.config.from_object(Config)


def login_required(f):
    """Decorador para proteger rotas que exigem login."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Por favor, faça login para acessar esta página.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Rota principal com formulário de criação de usuários."""
    if request.method == "POST":
        # Captura dados do formulário
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        username = request.form.get("username")
        password = request.form.get("password")
        profile_key = request.form.get("profile")

        # Validação básica
        if not all([first_name, last_name, username, password, profile_key]):
            flash("Por favor, preencha todos os campos.", "warning")
        else:
            # Tenta criar o usuário no AD
            success, message = create_ad_user(
                first_name, last_name, username, password, profile_key
            )

            if success:
                flash(message, "success")
                logger.info(
                    f"Sucesso Web: Usuário {username} criado por {session['user']}."
                )
            else:
                flash(f"Erro ao criar usuário: {message}", "danger")
                logger.error(f"Erro Web: {message}")

        return redirect(url_for("index"))

    # Carrega perfis para o dropdown
    perfis = Config.PERFIS
    return render_template("index.html", perfis=perfis)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Rota de autenticação via AD."""
    if "user" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if authenticate_user(username, password):
            session["user"] = username
            flash(f"Bem-vindo, {username}!", "success")
            return redirect(url_for("index"))
        else:
            flash("Credenciais inválidas ou sem acesso ao domínio.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Encerra a sessão do usuário."""
    session.pop("user", None)
    flash("Sessão encerrada com sucesso.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
