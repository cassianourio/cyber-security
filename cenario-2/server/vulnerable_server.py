import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_vuln.db")

# Initialize database with seed data
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create products table
    cursor.execute("DROP TABLE IF EXISTS products")
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)
    
    # Create users table
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    
    # Insert seed data
    cursor.executemany("INSERT INTO products (name, price, description) VALUES (?, ?, ?)", [
        ("Notebook Gamer", 4500.0, "Notebook de alta performance para jogos."),
        ("Mouse Sem Fio", 150.0, "Mouse ergonômico recarregável."),
        ("Teclado Mecânico", 350.0, "Teclado RGB com switches azuis."),
        ("Monitor 4K", 1800.0, "Monitor IPS de 27 polegadas profissional.")
    ])
    
    cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
        ("admin", "admin_super_secret_123", "admin"),
        ("user", "user12345", "user"),
        ("professor", "seguranca_da_informacao", "teacher")
    ])
    
    conn.commit()
    conn.close()

# HTML template for the vulnerable home dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laboratório de Teste SQL - Segurança III</title>
    <style>
        body {
            background-color: #0b0f19;
            color: #e5e7eb;
            font-family: sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem 1rem;
        }
        h1, h2 { color: #f97316; }
        .card {
            background: #111827;
            border: 1px solid #374151;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
        }
        input[type="text"], input[type="password"] {
            background: #1f2937;
            border: 1px solid #4b5563;
            color: white;
            padding: 0.5rem;
            border-radius: 4px;
            width: 100%;
            margin-bottom: 1rem;
            box-sizing: border-box;
        }
        button {
            background: #f97316;
            color: #0b0f19;
            font-weight: bold;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover { background: #ea580c; }
        pre {
            background: #1f2937;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            border-left: 4px solid #ef4444;
        }
        a { color: #f97316; }
    </style>
</head>
<body>
    <h1>Laboratório de Teste SQL Injection</h1>
    <p>Este é um servidor deliberadamente vulnerável para simulações e auditoria acadêmica.</p>
    
    <div class="card">
        <h2>Busca de Produtos (Vulnerabilidade GET)</h2>
        <p>Acesse o endpoint de busca de produtos passando o parâmetro <code>id</code>.</p>
        <p>Exemplo vulnerável: <a href="/products.php?id=1">/products.php?id=1</a></p>
        <p>Experimente injetar uma aspa: <a href="/products.php?id=1'">/products.php?id=1'</a></p>
    </div>

    <div class="card">
        <h2>Login de Usuários (Vulnerabilidade POST)</h2>
        <form action="/login" method="POST">
            <label for="username">Usuário:</label>
            <input type="text" id="username" name="username" placeholder="ex: admin">
            
            <label for="password">Senha:</label>
            <input type="password" id="password" name="password" placeholder="ex: 12345">
            
            <button type="submit">Autenticar</button>
        </form>
        {% if login_error %}
            <pre>{{ login_error }}</pre>
        {% endif %}
        {% if login_success %}
            <p style="color: #22c55e; font-weight: bold;">{{ login_success }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/products.php")
def get_product():
    product_id = request.args.get("id", "")
    if not product_id:
        return "Informe o parâmetro id na URL (ex: /products.php?id=1)", 400
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERÁVEL: concatenação direta de query SQL
    query = f"SELECT id, name, price, description FROM products WHERE id = {product_id}"
    
    try:
        cursor.execute(query)
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return jsonify({
                "id": row[0],
                "name": row[1],
                "price": row[2],
                "description": row[3]
            })
        else:
            return jsonify({"error": "Produto não encontrado"}), 404
            
    except Exception as e:
        conn.close()
        # Retorna o erro bruto contendo assinaturas típicas de banco de dados
        return f"Database operational error: near \"{product_id}\": syntax error. Raw trace: {str(e)}", 500

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERÁVEL: concatenação direta dos campos username e password
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return render_template_string(HTML_TEMPLATE, login_success=f"Autenticado com sucesso como {user[1]} (Função: {user[2]})")
        else:
            return render_template_string(HTML_TEMPLATE, login_error="Login falhou: Credenciais inválidas.")
            
    except Exception as e:
        conn.close()
        # Retorna o erro de sintaxe do SQL de forma descritiva
        return f"Database query compilation error: SQLite3 logic failed: {str(e)}", 500

if __name__ == "__main__":
    init_db()
    print("-----------------------------------------------------------------")
    print("Servidor Vulnerável de Teste rodando no endereço http://127.0.0.1:5002")
    print("Use-o como alvo no Scanner da porta 5001")
    print("-----------------------------------------------------------------")
    app.run(host="127.0.0.1", port=5002, debug=True)
