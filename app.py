# app.py
import sqlite3
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os, secrets
from functools import wraps
from flask_cors import CORS

APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(16)
app = Flask(__name__)
CORS(app) 
app.secret_key = APP_SECRET
DATABASE = 'database.db'

# ---------- DB Helpers ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            fullname TEXT
        );
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            owner_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        """)
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db: db.close()

# ---------- Auth & CSRF ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def generate_csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('_csrf', None)
        form_token = request.form.get('_csrf') or request.headers.get('X-CSRF-Token')
        if not token or not form_token or token != form_token:
            return "CSRF token missing or invalid", 400

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ---------- Routes ----------
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        fullname = request.form.get('fullname','')
        if not username or not password:
            flash('Usuário e senha são obrigatórios.')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password, fullname) VALUES (?, ?, ?)',
                       (username, hashed, fullname))
            db.commit()
            flash('Cadastro realizado com sucesso. Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['_csrf'] = secrets.token_hex(16)
            flash('Login efetuado.')
            return redirect(request.args.get('next') or url_for('index'))
        flash('Credenciais inválidas.')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Desconectado.')
    return redirect(url_for('login'))

@app.route('/items/new', methods=['GET','POST'])
@login_required
def new_item():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        description = request.form.get('description','').strip()
        if not title:
            flash('Título é obrigatório.')
            return redirect(url_for('new_item'))
        db = get_db()
        db.execute('INSERT INTO items (title, description, owner_id) VALUES (?, ?, ?)',
                   (title, description, session['user_id']))
        db.commit()
        flash('Item cadastrado.')
        return redirect(url_for('list_items'))
    return render_template('new_item.html')

@app.route('/items')
@login_required
def list_items():
    db = get_db()
    cur = db.execute('''
        SELECT items.id, items.title, items.description, items.created_at, users.username as owner
        FROM items LEFT JOIN users ON items.owner_id = users.id
        ORDER BY items.created_at DESC
    ''')
    items = cur.fetchall()
    return render_template('report.html', items=items)

@app.route('/api/items', methods=['GET'])
@login_required
def api_items():
    db = get_db()
    cur = db.execute('SELECT id, title, description, created_at FROM items ORDER BY created_at DESC')
    rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True)
