"""
Demo Broken Authentication / Session Management.

Reproduce (en laboratorio aislado) el hecho real: un estudiante copio la cookie
de sesion de un companiero y ambos quedaron dentro del sistema de inscripcion
AL MISMO TIEMPO. El sistema real queda detras de una sala de espera (Queue-it);
aqui se implementa una cola FIFO en el servidor + la sesion vulnerable detras.

Un solo codigo, dos modos (env DEMO_MODE=vuln|fixed) para mostrar el ataque y
luego la correccion en vivo. NO apunta a ningun sistema real.
"""
import os
import sqlite3
import secrets
import time
import math
from contextlib import closing

from flask import (Flask, request, redirect, url_for, render_template,
                   make_response, jsonify, abort)

MODE = os.environ.get("DEMO_MODE", "vuln").lower()
PORT = 8000
COOKIE = "sid"
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cola.db")

IDLE_TIMEOUT = 300       # 5 min sin actividad
ABSOLUTE_TIMEOUT = 1800  # 30 min de vida maxima
QUEUE_COOKIE = "queue_ticket"
QUEUE_INTERVAL = max(0.1, float(os.environ.get("QUEUE_INTERVAL", "3")))
QUEUE_IDLE_TIMEOUT = 120  # abandona la fila tras 2 min sin consultar
QUEUE_ADMISSION_TIMEOUT = 120  # 2 min para completar el login al obtener turno

app = Flask(__name__)

# Almacen de sesiones en memoria: sid -> {uid, user, nombre, ip, ua, created, last}
SESSIONS = {}


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password TEXT, nombre TEXT);
        CREATE TABLE IF NOT EXISTS ramos(
            id INTEGER PRIMARY KEY, uid INTEGER, sigla TEXT, nombre TEXT);
        CREATE TABLE IF NOT EXISTS queue_tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL,
            last_seen REAL NOT NULL, admitted_at REAL);
        CREATE TABLE IF NOT EXISTS queue_clock(
            id INTEGER PRIMARY KEY CHECK(id=1), next_admission REAL NOT NULL);
        INSERT OR IGNORE INTO queue_clock VALUES(1, 0);
        """
    )
    if not c.execute("SELECT 1 FROM users").fetchone():
        c.execute("INSERT INTO users VALUES(1,'estudiante1','clave123','Ana Diaz')")
        c.execute("INSERT INTO users VALUES(2,'estudiante2','panda2024','Luis Soto')")
        c.executemany(
            "INSERT INTO ramos(uid,sigla,nombre) VALUES(?,?,?)",
            [(1, "IIC2113", "Diseno de Software"),
             (1, "MAT1610", "Calculo I"),
             (2, "IIC2233", "Programacion Avanzada")],
        )
    c.commit()
    c.close()


def queue_state(join=False):
    """Avanza un turno por intervalo; SQLite serializa ingreso, consulta y limpieza."""
    token = request.cookies.get(QUEUE_COOKIE)
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        now = time.time()
        c.execute("DELETE FROM queue_tickets WHERE "
                  "(admitted_at IS NULL AND last_seen <= ?) OR admitted_at <= ?",
                  (now - QUEUE_IDLE_TIMEOUT, now - QUEUE_ADMISSION_TIMEOUT))
        ticket = c.execute("SELECT * FROM queue_tickets WHERE token=?", (token,)).fetchone()
        if ticket is None:
            if not join:
                c.commit()
                return None
            if not c.execute("SELECT 1 FROM queue_tickets WHERE admitted_at IS NULL").fetchone():
                c.execute("UPDATE queue_clock SET next_admission=? WHERE id=1",
                          (now + QUEUE_INTERVAL,))
            token = secrets.token_urlsafe(32)
            c.execute("INSERT INTO queue_tickets(token,last_seen) VALUES(?,?)", (token, now))
        c.execute("UPDATE queue_tickets SET last_seen=? WHERE token=?", (now, token))
        next_admission = c.execute("SELECT next_admission FROM queue_clock WHERE id=1").fetchone()[0]
        if now >= next_admission:
            first = c.execute("SELECT id FROM queue_tickets WHERE admitted_at IS NULL "
                              "ORDER BY id LIMIT 1").fetchone()
            if first:
                c.execute("UPDATE queue_tickets SET admitted_at=? WHERE id=?", (now, first[0]))
                next_admission = now + QUEUE_INTERVAL
                c.execute("UPDATE queue_clock SET next_admission=? WHERE id=1", (next_admission,))
        ticket = c.execute("SELECT * FROM queue_tickets WHERE token=?", (token,)).fetchone()
        admitted = ticket["admitted_at"] is not None
        position = 0 if admitted else c.execute(
            "SELECT COUNT(*) FROM queue_tickets WHERE admitted_at IS NULL AND id<=?",
            (ticket["id"],)).fetchone()[0]
        eta = 0 if admitted else math.ceil(max(0, next_admission - now) + (position - 1) * QUEUE_INTERVAL)
        c.commit()
        return dict(token=token, admitted=admitted, position=position, eta_seconds=eta)
    finally:
        c.close()


def consume_queue_ticket():
    """El permiso se usa una sola vez, incluso ante logins simultaneos."""
    c = db()
    try:
        with c:
            result = c.execute("DELETE FROM queue_tickets WHERE token=? AND admitted_at > ?",
                               (request.cookies.get(QUEUE_COOKIE), time.time() - QUEUE_ADMISSION_TIMEOUT))
        return result.rowcount == 1
    finally:
        c.close()


@app.after_request
def no_cached_queue(response):
    if request.endpoint in ("sala_espera", "queue_status", "login"):
        response.headers["Cache-Control"] = "no-store"
    return response


def new_sid(uid):
    # vuln: id predecible y adivinable (el del usuario). fixed: aleatorio de 256 bits.
    return str(uid) if MODE == "vuln" else secrets.token_urlsafe(32)


def current():
    sid = request.cookies.get(COOKIE)
    if not sid or sid not in SESSIONS:
        return None
    s = SESSIONS[sid]
    if MODE == "fixed":
        now = time.time()
        if now - s["created"] > ABSOLUTE_TIMEOUT or now - s["last"] > IDLE_TIMEOUT:
            SESSIONS.pop(sid, None)
            return None
        # sesion atada a la IP de origen -> una cookie robada desde otra maquina no sirve
        if s["ip"] != request.remote_addr:
            return None
        s["last"] = now
    return s


@app.route("/")
def sala_espera():
    state = queue_state(join=True)
    resp = make_response(render_template("sala_espera.html", mode=MODE,
                                        state={k: v for k, v in state.items() if k != "token"}))
    resp.set_cookie(QUEUE_COOKIE, state["token"], httponly=True, samesite="Strict",
                    secure=bool(os.environ.get("TLS_CERT")))
    return resp


@app.route("/queue/status")
def queue_status():
    state = queue_state()
    if state is None:
        return jsonify(error="Turno inexistente o vencido"), 401
    return jsonify({k: v for k, v in state.items() if k != "token"})


@app.route("/login", methods=["GET", "POST"])
def login():
    state = queue_state()
    if state is None or not state["admitted"]:
        return redirect(url_for("sala_espera"))
    if request.method == "POST":
        u = request.form.get("usuario", "")
        p = request.form.get("clave", "")
        with closing(db()) as c:
            row = c.execute(
                "SELECT * FROM users WHERE username=? AND password=?", (u, p)
            ).fetchone()
        if not row:
            return render_template("login.html", mode=MODE, error="Credenciales invalidas")

        if not consume_queue_ticket():
            return redirect(url_for("sala_espera"))
        now = time.time()
        if MODE == "vuln":
            # FIXATION: si ya viene un sid del cliente, se reutiliza; no se rota al loguear.
            sid = request.cookies.get(COOKIE) or new_sid(row["id"])
            SESSIONS[sid] = {"uid": row["id"], "user": row["username"],
                             "nombre": row["nombre"], "ip": None, "ua": None,
                             "created": now, "last": now}
            resp = make_response(redirect(url_for("dashboard")))
            # cookie sin HttpOnly / Secure / SameSite
            resp.set_cookie(COOKIE, sid)
        else:
            # rotacion de sesion al autenticar + atado a IP/UA + flags de cookie
            old = request.cookies.get(COOKIE)
            SESSIONS.pop(old, None)
            sid = new_sid(row["id"])
            SESSIONS[sid] = {"uid": row["id"], "user": row["username"],
                             "nombre": row["nombre"], "ip": request.remote_addr,
                             "ua": request.headers.get("User-Agent", ""),
                             "created": now, "last": now}
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(COOKIE, sid, httponly=True, samesite="Strict",
                            secure=bool(os.environ.get("TLS_CERT")))
        resp.delete_cookie(QUEUE_COOKIE)
        return resp
    return render_template("login.html", mode=MODE)


@app.route("/dashboard")
def dashboard():
    s = current()
    if not s:
        return redirect(url_for("login"))
    with closing(db()) as c:
        ramos = c.execute("SELECT sigla,nombre FROM ramos WHERE uid=?", (s["uid"],)).fetchall()
    sid = request.cookies.get(COOKIE)
    return render_template("dashboard.html", mode=MODE, s=s, ramos=ramos, sid=sid)


@app.route("/whoami")
def whoami():
    # usado por el atacante (hijack.sh) para probar si la cookie copiada da acceso
    s = current()
    if not s:
        return jsonify(autenticado=False), 401
    return jsonify(autenticado=True, usuario=s["user"], nombre=s["nombre"],
                   ip_sesion=s["ip"], ip_peticion=request.remote_addr)


@app.route("/logout")
def logout():
    SESSIONS.pop(request.cookies.get(COOKIE), None)
    resp = make_response(redirect(url_for("sala_espera")))
    resp.delete_cookie(COOKIE)
    return resp


if __name__ == "__main__":
    init_db()
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    ctx = (cert, key) if cert and key and os.path.exists(cert) else None
    print(f"[cola] DEMO_MODE={MODE} TLS={'on' if ctx else 'off'} :{PORT}")
    app.run(host="0.0.0.0", port=PORT, ssl_context=ctx, threaded=True)
