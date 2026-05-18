import os
import sqlite3
import socket
import datetime
import secrets
from flask import Flask, request, jsonify, render_template, g

app = Flask(__name__, static_folder='static')

# ── Initialize in-memory SQLite database ─────────────────────────────────────
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT, department TEXT
    )''')
    conn.executemany('INSERT INTO users VALUES (?,?,?,?,?)', [
        (1,'alice',  'alice@corp.local',  'admin',  'Engineering'),
        (2,'bob',    'bob@corp.local',    'user',   'Marketing'),
        (3,'charlie','charlie@corp.local','user',   'Finance'),
        (4,'diana',  'diana@corp.local',  'manager','Engineering'),
        (5,'eve',    'eve@corp.local',    'admin',  'Security'),
        (6,'frank',  'frank@corp.local',  'user',   'HR'),
    ])
    conn.commit()
    return conn

DB = init_db()

def ctx():
    return {
        'hostname':    socket.gethostname(),
        'environment': os.environ.get('ENVIRONMENT', 'dev'),
        'version':     os.environ.get('APP_VERSION', '2.0.0-secure'),
        'deploy_time': os.environ.get('DEPLOY_TIME', 'unknown'),
        'commit_sha':  os.environ.get('COMMIT_SHA', 'local')[:7],
        'port':        os.environ.get('HOST_PORT', '5000'),
    }


# ── Generate a CSP nonce per request ─────────────────────────────────────────
@app.before_request
def generate_nonce():
    g.nonce = secrets.token_hex(16)


# ── Security headers on every response ───────────────────────────────────────
@app.after_request
def set_security_headers(response):
    nonce = getattr(g, 'nonce', '')

    # CSP — no unsafe-inline; style-src uses per-request nonce
    # form-action 'self' prevents form hijacking (fixes ZAP form-action finding)
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none';"
    )
    response.headers['X-Frame-Options']               = 'DENY'
    response.headers['X-Content-Type-Options']        = 'nosniff'
    response.headers['Cross-Origin-Embedder-Policy']  = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy']    = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy']  = 'same-origin'
    response.headers['Permissions-Policy']            = (
        'camera=(), microphone=(), geolocation=(), payment=()'
    )
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
    response.headers['Pragma']        = 'no-cache'
    response.headers['Expires']       = '0'
    return response


# ── WSGI middleware to override Server header ─────────────────────────────────
# after_request cannot override the Server header — Werkzeug sets it at the
# WSGI layer after Flask has finished. This middleware intercepts it correctly.
class HideServerVersion:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            headers = [(k, v) for k, v in headers if k.lower() != 'server']
            headers.append(('Server', 'CorpDirectory'))
            return start_response(status, headers, exc_info)
        return self.wsgi_app(environ, custom_start_response)

app.wsgi_app = HideServerVersion(app.wsgi_app)


@app.route('/')
def index():
    return render_template('index.html', nonce=g.nonce, **ctx())


# ── FIX 1: Parameterized query ────────────────────────────────────────────────
@app.route('/search')
def search():
    q = request.args.get('q', '')
    results, error = [], None
    if q:
        try:
            cursor = DB.execute(
                "SELECT * FROM users WHERE username = ?", (q,)
            )
            results = cursor.fetchall()
        except Exception as e:
            error = str(e)
    return render_template('search.html', q=q, results=results,
                           error=error, nonce=g.nonce, **ctx())


# ── FIX 2: /debug removed ────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({
        'status':  'ok',
        'app':     'corpdirectory',
        'version': os.environ.get('APP_VERSION', '2.0.0-secure'),
        'env':     os.environ.get('ENVIRONMENT', 'dev'),
        'host':    socket.gethostname(),
        'time':    datetime.datetime.utcnow().isoformat() + 'Z',
    })


if __name__ == '__main__':
    # FIX 3: debug=False
    app.run(host='0.0.0.0', port=5000, debug=False)
