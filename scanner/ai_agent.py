import json
import vertexai
from vertexai.generative_models import GenerativeModel
import config

def analyze_vulnerabilities(scan_data):
    """
    Sends the gathered scanning data to Gemini using Vertex AI for analysis.
    """
    print(f"[*] Inicializando o agente de IA Vertex AI ({config.GEMINI_MODEL}) para diagnóstico...")
    
    # Initialize Vertex AI with parameters from config
    vertexai.init(project=config.GCP_PROJECT, location=config.GCP_LOCATION)
    
    # Instantiate the model
    model = GenerativeModel(config.GEMINI_MODEL)
    
    # Format the scanning data to JSON for the prompt
    formatted_data = json.dumps(scan_data, indent=2, ensure_ascii=False)
    
    # Prompt engineering for the security agent
    prompt = f"""
Você é um auditor sênior de segurança da informação especializado em infraestrutura web.
Analise os resultados brutos da varredura realizada no servidor alvo abaixo e crie um **Relatório de Diagnóstico de Vulnerabilidades** formal em Markdown.

Dados brutos da varredura:
```json
{formatted_data}
```

O relatório deve conter obrigatoriamente as seguintes seções estruturadas:

1. **Título do Relatório:** "Relatório de Diagnóstico de Segurança Web - [Nome do Alvo]"
2. **Resumo Executivo:** Um sumário rápido e em alto nível sobre o estado de segurança do servidor.
3. **Classificação Geral de Risco:** Defina um nível geral de risco para o alvo: CRÍTICO, ALTO, MÉDIO, BAIXO ou INFORMATIVO, justificando brevemente.
4. **Análise de Criptografia SSL/TLS & Certificados (Cenário 1):**
    - Analise as versões de TLS habilitadas. Identifique se versões obsoletas/inseguras como TLS 1.0 ou 1.1 estão ativas (que devem ser desativadas).
    - Avalie o certificado digital SSL: validade, dias restantes antes da expiração, assinatura e integridade.
5. **Análise de Cabeçalhos HTTP & Configurações de Servidor (Cenário 1):**
    - Identifique quais cabeçalhos de segurança essenciais estão ausentes (ex: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
    - Avalie os riscos associados à ausência de cada cabeçalho (ex: vulnerabilidade a Clickjacking, XSS, MIME sniffing, etc.).
    - Verifique se há vazamento de informações (Server banner disclosure) nos cabeçalhos 'Server' ou 'X-Powered-By'.
    - Analise se os cookies (se houver) estão configurados com as flags HttpOnly, Secure e SameSite.
6. **Tabela Consolidade de Vulnerabilidades:**
    Uma tabela Markdown contendo as colunas:
    - **ID/Vulnerabilidade**: Nome do problema (ex: "TLS 1.0 Habilitado", "HSTS Ausente").
    - **Severidade**: Classificação de risco específica da vulnerabilidade (Crítica, Alta, Média, Baixa, Informativa).
    - **Impacto**: O que um atacante pode fazer explorando isso.
    - **Mitigação Recomendada**: Uma breve ação corretiva.
7. **Instruções Detalhadas de Correção:**
    Forneça trechos de código/configurações práticos de mitigação para servidores Web populares:
    - Exemplo de configuração recomendada para o **Nginx** (`nginx.conf`).
    - Exemplo de configuração recomendada para o **Apache** (`.htaccess` ou `httpd.conf`).
    - Boas práticas gerais de segurança no servidor web.

**Instruções de Estilo:**
- Escreva o relatório inteiramente em **Português (Brasil)**.
- Use tom profissional, técnico e objetivo.
- Use elementos Markdown como tabelas, listas e blocos de código para tornar o documento legível e acionável.
- Não inclua explicações ou conversas fora do relatório. Retorne apenas o conteúdo em Markdown.
"""

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"[!] Erro ao chamar a API do Vertex AI: {e}")
        return f"# Erro no Diagnóstico\nOcorreu um erro ao processar os dados com o Gemini: {e}"
