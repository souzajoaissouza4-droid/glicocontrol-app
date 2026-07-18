import os
import re
import json
import base64
import sqlite3
import random
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai_client = None
if OPENAI_API_KEY:
    try:
        from openai import OpenAI
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        # Se a inicialização do cliente falhar por qualquer motivo (chave
        # inválida, dependência incompatível, etc.), o app continua no ar
        # em modo simulado em vez de derrubar o serviço inteiro.
        openai_client = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "glicocontrol.db")

app = Flask(__name__, template_folder=BASE_DIR, static_folder=None)
app.secret_key = os.environ.get("SECRET_KEY", "troque-esta-chave-em-producao")

# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS meals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            carbs_g INTEGER NOT NULL,
            glucose_impact TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Faça login para continuar.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=("GET", "POST"))
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        error = None
        if not name:
            error = "Informe seu nome."
        elif not email:
            error = "Informe seu e-mail."
        elif not password or len(password) < 6:
            error = "A senha precisa ter pelo menos 6 caracteres."

        if error is None:
            db = get_db()
            existing = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing is not None:
                error = "Já existe uma conta com esse e-mail."

        if error is None:
            db = get_db()
            db.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
            )
            db.commit()
            flash("Conta criada! Faça login para continuar.", "success")
            return redirect(url_for("login"))

        flash(error, "error")

    return render_template("signup.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        error = None
        if user is None:
            error = "E-mail ou senha incorretos."
        elif not check_password_hash(user["password_hash"], password):
            error = "E-mail ou senha incorretos."

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("dashboard"))

        flash(error, "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# App principal
# ---------------------------------------------------------------------------

MOCK_FOODS = [
    ("Arroz, feijão e frango grelhado", 45, "Moderado"),
    ("Salada com quinoa e legumes", 22, "Baixo"),
    ("Pão francês com manteiga", 38, "Moderado"),
    ("Refrigerante e batata frita", 78, "Alto"),
    ("Omelete com vegetais", 8, "Baixo"),
    ("Macarrão à bolonhesa", 62, "Alto"),
    ("Iogurte natural com frutas", 18, "Baixo"),
    ("Feijoada completa", 55, "Moderado"),
]


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    meals = db.execute(
        "SELECT * FROM meals WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", meals=meals, user_name=session.get("user_name"))


def analisar_refeicao_com_ia(arquivo_imagem):
    """Envia a foto da refeição para o modelo de visão da OpenAI e retorna
    (description, carbs_g, glucose_impact). Lança exceção se a chamada falhar."""
    imagem_bytes = arquivo_imagem.read()
    imagem_b64 = base64.b64encode(imagem_bytes).decode("utf-8")
    mime = arquivo_imagem.mimetype or "image/jpeg"

    prompt = (
        "Você é um assistente nutricional. Olhe a foto da refeição e responda "
        "APENAS com um JSON válido, sem texto adicional, no formato exato: "
        '{"description": "nome curto do prato em português", '
        '"carbs_g": numero_inteiro_de_gramas_de_carboidrato_estimado, '
        '"glucose_impact": "Baixo" ou "Moderado" ou "Alto"}'
    )

    resposta = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{imagem_b64}"},
                    },
                ],
            }
        ],
        max_tokens=200,
    )

    texto = resposta.choices[0].message.content.strip()
    # Remove possíveis blocos de código (```json ... ```) que o modelo às vezes adiciona.
    texto = re.sub(r"^```(json)?|```$", "", texto.strip(), flags=re.MULTILINE).strip()
    dados = json.loads(texto)

    description = str(dados["description"])[:200]
    carbs_g = int(dados["carbs_g"])
    glucose_impact = str(dados["glucose_impact"]).capitalize()
    if glucose_impact not in ("Baixo", "Moderado", "Alto"):
        glucose_impact = "Moderado"

    return description, carbs_g, glucose_impact


@app.route("/scan", methods=("GET", "POST"))
@login_required
def scan():
    if request.method == "POST":
        foto = request.files.get("photo")
        usar_ia_real = openai_client is not None and foto is not None and foto.filename

        if usar_ia_real:
            try:
                description, carbs_g, glucose_impact = analisar_refeicao_com_ia(foto)
                mensagem = "Refeição analisada pela IA!"
            except Exception as exc:
                app.logger.error("Falha na análise por IA: %s", exc)
                description, carbs_g, glucose_impact = random.choice(MOCK_FOODS)
                mensagem = "Não consegui analisar a foto agora, usei uma estimativa (modo simulado)."
        else:
            # Sem chave de IA configurada (OPENAI_API_KEY) ou sem foto enviada:
            # cai no modo simulado para não travar a demonstração.
            description, carbs_g, glucose_impact = random.choice(MOCK_FOODS)
            mensagem = "Refeição analisada! (modo simulado — IA real ainda não conectada)"

        db = get_db()
        db.execute(
            "INSERT INTO meals (user_id, description, carbs_g, glucose_impact, created_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], description, carbs_g, glucose_impact, datetime.utcnow().isoformat()),
        )
        db.commit()
        flash(mensagem, "success")
        return redirect(url_for("dashboard"))

    return render_template("scan.html")


# Garante que as tabelas existem sempre que o módulo é carregado, seja rodando
# diretamente (`python glicocontrol_app.py`) ou importado por um servidor WSGI
# como o gunicorn (`gunicorn glicocontrol_app:app`), que nunca executa o bloco
# `if __name__ == "__main__":` abaixo.
init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
