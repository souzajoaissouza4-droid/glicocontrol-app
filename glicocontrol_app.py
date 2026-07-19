import os
import re
import json
import base64
import sqlite3
import random
from datetime import datetime, timedelta
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

# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------
# Se a variável de ambiente DATABASE_URL estiver definida (ex.: um Postgres
# do Render), usamos ela — os dados ficam persistentes de verdade, mesmo
# quando o serviço "dorme" e acorda de novo (o disco local do Render free
# tier não é persistente e o SQLite se perderia a cada reinício).
# Sem DATABASE_URL, cai no SQLite local (bom para rodar na sua máquina).
DATABASE_URL = os.environ.get("DATABASE_URL")
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

    # Render às vezes fornece a URL como "postgres://", mas psycopg2 aceita
    # tanto "postgres://" quanto "postgresql://" normalmente. Mantemos como
    # veio, só garantindo o sslmode exigido pelo Render.
    _DB_URL = DATABASE_URL


def _pg_connect():
    conn = psycopg2.connect(_DB_URL, sslmode="require")
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


app = Flask(__name__, template_folder=BASE_DIR, static_folder=None)
app.secret_key = os.environ.get("SECRET_KEY", "troque-esta-chave-em-producao")


def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            g.db = _pg_connect()
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _sql(query):
    """Converte os placeholders '?' (estilo SQLite, usados em todo o código)
    para '%s' (estilo Postgres/psycopg2) quando estamos usando Postgres."""
    return query.replace("?", "%s") if USE_POSTGRES else query


def db_execute(query, params=()):
    """Executa um INSERT/UPDATE/DELETE e faz commit."""
    db = get_db()
    cur = db.cursor()
    cur.execute(_sql(query), params)
    db.commit()
    cur.close()


def db_query_one(query, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(_sql(query), params)
    row = cur.fetchone()
    cur.close()
    return row


def db_query_all(query, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(_sql(query), params)
    rows = cur.fetchall()
    cur.close()
    return rows


def init_db():
    if USE_POSTGRES:
        conn = _pg_connect()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS meals (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id),
                description TEXT NOT NULL,
                carbs_g INTEGER NOT NULL,
                glucose_impact TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        cur.close()
        conn.close()
    else:
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
            return redirect(url_for("login", next=request.path))
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
            existing = db_query_one("SELECT id FROM users WHERE email = ?", (email,))
            if existing is not None:
                error = "Já existe uma conta com esse e-mail."

        if error is None:
            db_execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
            )
            flash("Conta criada! Faça login para continuar.", "success")
            return redirect(url_for("login"))

        flash(error, "error")

    return render_template("signup.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db_query_one("SELECT * FROM users WHERE email = ?", (email,))

        error = None
        if user is None:
            error = "E-mail ou senha incorretos."
        elif not check_password_hash(user["password_hash"], password):
            error = "E-mail ou senha incorretos."

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            destino = request.form.get("next") or request.args.get("next")
            if destino and destino.startswith("/"):
                return redirect(destino)
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


def _resumo_semanal(lista_refeicoes):
    total = len(lista_refeicoes)
    altos = sum(1 for m in lista_refeicoes if m["glucose_impact"] == "Alto")
    moderados = sum(1 for m in lista_refeicoes if m["glucose_impact"] == "Moderado")
    baixos = sum(1 for m in lista_refeicoes if m["glucose_impact"] == "Baixo")
    pct_alto = round((altos / total) * 100) if total else 0
    return {
        "total": total,
        "altos": altos,
        "moderados": moderados,
        "baixos": baixos,
        "pct_alto": pct_alto,
    }


@app.route("/dashboard")
@login_required
def dashboard():
    meals = db_query_all(
        "SELECT * FROM meals WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
        (session["user_id"],),
    )

    agora = datetime.utcnow()
    inicio_semana_atual = (agora - timedelta(days=7)).isoformat()
    inicio_semana_anterior = (agora - timedelta(days=14)).isoformat()

    semana_atual = db_query_all(
        "SELECT * FROM meals WHERE user_id = ? AND created_at >= ? ORDER BY created_at DESC",
        (session["user_id"], inicio_semana_atual),
    )
    semana_anterior = db_query_all(
        "SELECT * FROM meals WHERE user_id = ? AND created_at >= ? AND created_at < ?",
        (session["user_id"], inicio_semana_anterior, inicio_semana_atual),
    )

    insights = _resumo_semanal(semana_atual)
    insights_anterior = _resumo_semanal(semana_anterior)

    tendencia = None
    if insights["total"] >= 1 and insights_anterior["total"] >= 1:
        if insights["pct_alto"] < insights_anterior["pct_alto"]:
            tendencia = "melhorando"
        elif insights["pct_alto"] > insights_anterior["pct_alto"]:
            tendencia = "piorando"
        else:
            tendencia = "estavel"

    return render_template(
        "dashboard.html",
        meals=meals,
        user_name=session.get("user_name"),
        insights=insights,
        tendencia=tendencia,
    )


MOCK_DICAS = {
    "Baixo": "Ótima escolha! Continue priorizando fibra e proteína nas próximas refeições.",
    "Moderado": "Impacto moderado — experimente reduzir um pouco a porção do carboidrato principal na próxima refeição parecida.",
    "Alto": "Impacto alto — na próxima vez, tente combinar esse tipo de prato com mais fibra ou proteína, ou reduzir a porção.",
}


def analisar_refeicao_com_ia(arquivo_imagem):
    """Envia a foto da refeição para o modelo de visão da OpenAI e retorna
    (description, carbs_g, glucose_impact, dica). Lança exceção se a chamada falhar."""
    imagem_bytes = arquivo_imagem.read()
    imagem_b64 = base64.b64encode(imagem_bytes).decode("utf-8")
    mime = arquivo_imagem.mimetype or "image/jpeg"

    prompt = (
        "Você é um assistente nutricional. Olhe a foto da refeição e responda "
        "APENAS com um JSON válido, sem texto adicional, no formato exato: "
        '{"description": "nome curto do prato em português", '
        '"carbs_g": numero_inteiro_de_gramas_de_carboidrato_estimado, '
        '"glucose_impact": "Baixo" ou "Moderado" ou "Alto", '
        '"dica": "uma dica prática, curta (máximo 1 frase) e específica sobre essa refeição, em português"}'
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
        max_tokens=300,
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
    dica = str(dados.get("dica", "")).strip()[:300] or MOCK_DICAS.get(glucose_impact, "")

    return description, carbs_g, glucose_impact, dica


@app.route("/scan", methods=("GET", "POST"))
@login_required
def scan():
    if request.method == "POST":
        foto = request.files.get("photo")
        usar_ia_real = openai_client is not None and foto is not None and foto.filename

        if usar_ia_real:
            try:
                description, carbs_g, glucose_impact, dica = analisar_refeicao_com_ia(foto)
                mensagem = f"Refeição analisada pela IA! 💡 {dica}" if dica else "Refeição analisada pela IA!"
            except Exception as exc:
                app.logger.error("Falha na análise por IA: %s", exc)
                description, carbs_g, glucose_impact = random.choice(MOCK_FOODS)
                dica = MOCK_DICAS.get(glucose_impact, "")
                mensagem = f"Não consegui analisar a foto agora, usei uma estimativa (modo simulado). 💡 {dica}"
        else:
            # Sem chave de IA configurada (OPENAI_API_KEY) ou sem foto enviada:
            # cai no modo simulado para não travar a demonstração.
            description, carbs_g, glucose_impact = random.choice(MOCK_FOODS)
            dica = MOCK_DICAS.get(glucose_impact, "")
            mensagem = f"Refeição analisada! (modo simulado — IA real ainda não conectada) 💡 {dica}"

        db_execute(
            "INSERT INTO meals (user_id, description, carbs_g, glucose_impact, created_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], description, carbs_g, glucose_impact, datetime.utcnow().isoformat()),
        )
        flash(mensagem, "success")
        return redirect(url_for("dashboard"))

    return render_template("scan.html")


# ---------------------------------------------------------------------------
# Produtos digitais avulsos (order bump / upsell vendidos na Cakto)
# ---------------------------------------------------------------------------

@app.route("/guia-alimentacao")
def guia_alimentacao():
    return render_template("guia_alimentacao.html")


@app.route("/receitas-low-carb")
def receitas_low_carb():
    return render_template("receitas_low_carb.html")


MIN_REFEICOES_PARA_PLANO_IA = 3


def gerar_plano_personalizado_com_ia(meals, user_name):
    """Usa o histórico real de refeições escaneadas do usuário para gerar um
    plano alimentar semanal personalizado em texto (Markdown simples).
    Lança exceção se a chamada à IA falhar."""
    historico = "\n".join(
        f"- {m['description']} | carboidrato estimado: {m['carbs_g']}g | impacto na glicose: {m['glucose_impact']}"
        for m in meals
    )

    prompt = (
        f"Você é um assistente nutricional. O usuário se chama {user_name} e este é o "
        f"histórico real das últimas refeições que ele escaneou no app GlicoControl:\n\n"
        f"{historico}\n\n"
        "Com base APENAS nesse histórico (identifique padrões: horários, tipos de "
        "refeição ou alimentos com impacto alto/moderado na glicose), escreva um plano "
        "alimentar semanal personalizado em português, em Markdown simples, com:\n"
        "1) Um parágrafo curto resumindo os padrões que você notou no histórico dele.\n"
        "2) Uma lista de 3 a 5 ajustes práticos e específicos para essa pessoa (não "
        "genéricos), citando as refeições do histórico quando fizer sentido.\n"
        "3) Uma sugestão de cardápio para os próximos 3 dias (café da manhã, almoço, "
        "lanche, jantar), levando em conta o padrão identificado.\n"
        "Não inclua avisos médicos (isso já aparece em outro lugar da página). "
        "Seja direto e específico, evite generalidades."
    )

    resposta = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=900,
    )
    return resposta.choices[0].message.content.strip()


@app.route("/plano-alimentar")
@login_required
def plano_alimentar():
    meals = db_query_all(
        "SELECT * FROM meals WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
        (session["user_id"],),
    )

    plano_ia = None
    erro_ia = None
    if len(meals) >= MIN_REFEICOES_PARA_PLANO_IA:
        if openai_client is not None:
            try:
                plano_ia = gerar_plano_personalizado_com_ia(meals, session.get("user_name") or "")
            except Exception as exc:
                app.logger.error("Falha ao gerar plano personalizado com IA: %s", exc)
                erro_ia = "Não consegui gerar seu plano personalizado agora. Tente novamente em instantes."
        else:
            erro_ia = "IA ainda não configurada neste ambiente."

    return render_template(
        "plano_alimentar.html",
        meals_count=len(meals),
        min_refeicoes=MIN_REFEICOES_PARA_PLANO_IA,
        plano_ia=plano_ia,
        erro_ia=erro_ia,
    )


# Garante que as tabelas existem sempre que o módulo é carregado, seja rodando
# diretamente (`python glicocontrol_app.py`) ou importado por um servidor WSGI
# como o gunicorn (`gunicorn glicocontrol_app:app`), que nunca executa o bloco
# `if __name__ == "__main__":` abaixo.
init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
