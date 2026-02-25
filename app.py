from flask import Flask, render_template, request, flash, redirect, url_for, session
from functools import wraps
from config import Config
from ad_logic import (
    create_ad_user,
    authenticate_user,
    user_exists,
    search_users,
    get_user_details,
)
from flask import jsonify
from email_utils import send_provisioning_email
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


@app.route("/")
@login_required
def index():
    """Rota principal: Dashboard / Command Center."""
    return render_template("index.html")


@app.route("/create_user", methods=["GET", "POST"])
@login_required
def create_user():
    """Rota para o formulário de criação de usuários (Provisioning)."""
    if request.method == "POST":
        # Captura todos os novos campos do formulário
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        job_title = request.form.get("job_title")
        department = request.form.get("department")
        username = request.form.get("username")
        password = request.form.get("password")
        profile_key = request.form.get("profile")
        office_location = request.form.get("office_location")
        employee_id = request.form.get("employee_id")

        # 1. Validação se existe
        if user_exists(username):
            flash(
                f"Erro: O usuário '{username}' já existe no Active Directory.", "danger"
            )
            return redirect(url_for("create_user"))

        # 2. Tenta criar o usuário no AD
        success, message = create_ad_user(
            first_name,
            last_name,
            username,
            password,
            profile_key,
            job_title=job_title,
            department=department,
            office_location=office_location,
            employee_id=employee_id,
        )

        if success:
            flash(message, "success")
            logger.info(
                f"Sucesso Web: Usuário {username} criado por {session['user']}."
            )

            # 3. Enviar e-mail de notificação
            user_data = {
                "first_name": first_name,
                "last_name": last_name,
                "username": username,
                "job_title": job_title,
                "department": department,
            }
            send_provisioning_email(user_data)
        else:
            flash(f"Erro ao criar usuário: {message}", "danger")
            logger.error(f"Erro Web: {message}")

        return redirect(url_for("create_user"))

    # Carrega perfis para o dropdown
    perfis = Config.PERFIS
    return render_template("create_user.html", perfis=perfis)


@app.route("/groups")
@login_required
def groups():
    """Gerenciamento e pesquisa de usuários e grupos."""
    query = request.args.get("q", "")
    results = []
    if query:
        results = search_users(query)
    return render_template("groups.html", results=results, query=query)


@app.route("/audit")
@login_required
def audit():
    """Placeholder para logs de auditoria."""
    return render_template("audit.html")


@app.route("/user_profile/<username>")
@login_required
def user_profile(username):
    """Rota para exibir o perfil detalhado do usuário."""
    user_data = get_user_details(username)
    if not user_data:
        flash(f"Usuário '{username}' não encontrado.", "danger")
        return redirect(url_for("groups"))
    return render_template("user_profile.html", user=user_data)


@app.route("/user/<username>")
@login_required
def get_user(username):
    """API para retornar detalhes de um usuário em JSON."""
    details = get_user_details(username)
    if details:
        return jsonify(details)
    return jsonify({"error": "Usuário não encontrado"}), 404


@app.route("/login", methods=["GET", "POST"])
def login():
    """Rota de autenticação via AD com restrição de OU."""
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
            flash(
                "Credenciais inválidas ou você não tem permissão para acessar este portal.",
                "danger",
            )

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Encerra a sessão do usuário."""
    session.pop("user", None)
    flash("Sessão encerrada com sucesso.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=8080)
