import os
import sys
from datetime import datetime
from flask import Flask, request, jsonify, render_template

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from scanner.sql_scanner import run_sqli_scan, clean_hostname
from scanner.ai_agent import analyze_vulnerabilities

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/report/<filename>")
def view_report(filename):
    safe_filename = os.path.basename(filename)
    report_path = config.REPORTS_DIR / safe_filename
    if not report_path.exists() or not report_path.is_file():
        return "Relatório não encontrado.", 404
        
    with open(report_path, "r", encoding="utf-8") as f:
        report_content = f.read()
        
    return render_template("report.html", report_content=report_content)

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "O endereço da aplicação alvo é obrigatório"}), 400
        
    clean_host = clean_hostname(target)
    
    if clean_host == "teste-sql.com":
        ssl_results = {} # SQL Injection focuses on database errors, so we mock SQL scan results
        scan_results = {
            "target_url": target,
            "is_vulnerable": True,
            "forms_found": [
                {
                    "action": "http://teste-sql.com/login.php",
                    "method": "POST",
                    "inputs": ["username", "password"]
                }
            ],
            "vulnerabilities": [
                {
                    "type": "GET",
                    "parameter": "id",
                    "payload": "' OR 1=1 --",
                    "url_tested": "http://teste-sql.com/products.php?id=%27+OR+1%3D1+--",
                    "vulnerability_type": "Error-based SQL Injection",
                    "db_engine": "MySQL",
                    "error_signature": "you have an error in your sql syntax"
                },
                {
                    "type": "POST",
                    "action": "http://teste-sql.com/login.php",
                    "parameter": "username",
                    "payload": "' OR '1'='1",
                    "vulnerability_type": "Error-based SQL Injection (Form)",
                    "db_engine": "MySQL",
                    "error_signature": "you have an error in your sql syntax"
                }
            ]
        }
        ai_report = """# Relatório de Diagnóstico de Segurança de Banco de Dados - teste-sql.com

## Resumo Executivo
O sistema web **teste-sql.com** apresenta vulnerabilidades **CRÍTICAS** de injeção de comandos SQL (SQL Injection). Foram identificadas falhas de validação de dados tanto em parâmetros da URL (GET) quanto em campos de formulários (POST), permitindo a manipulação direta do interpretador do banco de dados remoto MySQL.

## Classificação Geral de Risco: **CRÍTICO**

## Análise de Pontos de Entrada e Vulnerabilidades
- **Parâmetro GET 'id' (`/products.php?id=`)**: Vulnerável a SQLi baseada em erro. Ao enviar a carga útil `' OR 1=1 --`, o servidor retornou uma falha de sintaxe descritiva revelando o uso de MySQL.
- **Campo de Formulário 'username' (`/login.php`)**: Vulnerável a SQLi. O formulário de login de usuários aceita payloads lógicos (ex: `' OR '1'='1`) permitindo o desvio completo do controle de autenticação (Authentication Bypass).

## Avaliação de Exposição de Dados
- **Bypass de Autenticação**: Um invasor pode acessar o painel administrativo sem possuir credenciais válidas.
- **Vazamento de Informações**: Um invasor pode usar consultas UNION para ler e despejar dados de qualquer tabela do banco (ex: dados de cartão de crédito, informações pessoais de clientes e hashes de senhas).
- **Escalação de privilégios**: Dependendo das permissões da conexão do banco de dados, pode ser possível ler e escrever arquivos no disco do servidor web.

## Tabela Consolidade de Vulnerabilidades
| ID/Vulnerabilidade | Severidade | Impacto | Mitigação Recomendada |
| --- | --- | --- | --- |
| SQLi no Parâmetro 'id' | Crítica | Acesso não autorizado e extração de tabelas | Implementar consultas parametrizadas (Prepared Statements) |
| SQLi no Formulário de Login | Crítica | Desvio total de controle de autenticação (Bypass) | Implementar consultas parametrizadas na checagem de credenciais |
| Exposição de Versão do SGBD | Baixa | Divulgação de assinatura para engenharia social / exploits | Ocultar ou desabilitar exibição pública de erros do PHP/MySQL |

## Instruções Detalhadas de Correção

A única mitigação definitiva e robusta contra SQL Injection é a separação dos dados de entrada do usuário dos comandos executados pelo banco de dados através de **Prepared Statements**.

### Correção com PHP PDO (Recomendado)
```php
// Inseguro:
// $query = "SELECT * FROM users WHERE username = '$user' AND password = '$password'";

// Seguro (Prepared Statement):
$stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = :username');
$stmt->execute(['username' => $user]);
$user_data = $stmt->fetch();
```

### Correção em Python (PEP 249)
```python
# Inseguro:
# cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")

# Seguro (Parameterized):
cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
```
"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"relatorio_teste-sql.com_{timestamp}.md"
        report_path = config.REPORTS_DIR / report_filename
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(ai_report)

        return jsonify({
            "success": True,
            "scan_results": scan_results,
            "ai_report": ai_report,
            "report_filename": report_filename,
            "report_path": str(report_path.absolute())
        })

    try:
        scan_results = run_sqli_scan(target)
        
        consolidated_scan = {
            "scan_timestamp": datetime.now().isoformat(),
            "target": {
                "input": target,
                "hostname": clean_host
            },
            "sqli_diagnostics": scan_results
        }
        
        ai_report = analyze_vulnerabilities(consolidated_scan)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"relatorio_{clean_host}_{timestamp}.md"
        report_path = config.REPORTS_DIR / report_filename
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(ai_report)
            
        return jsonify({
            "success": True,
            "scan_results": scan_results,
            "ai_report": ai_report,
            "report_filename": report_filename,
            "report_path": str(report_path.absolute())
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
