# Cyber Security Projects

Este repositório reúne projetos práticos de segurança da informação desenvolvidos para fins acadêmicos e de demonstração prática. O repositório está organizado em múltiplos cenários e desafios de segurança.

---

## Cenários Disponíveis

### [Cenário 1 - Diagnóstico Automatizado de Vulnerabilidades Web](./cenario-1)
Uma aplicação web completa (dashboard SPA com Flask, HTML5, Vanilla CSS e JS) que realiza auditoria automática de servidores web:
- Varredura local de handshakes de criptografia SSL/TLS e análise de validade e metadados de certificados digitais.
- Varredura de cabeçalhos de segurança HTTP (como CSP, HSTS, X-Frame-Options) e análise de flags de segurança em cookies.
- Consolidação dos dados e envio para o **Google Cloud Vertex AI (Gemini)** para geração de um relatório de diagnóstico automatizado e mitigações recomendadas para Nginx/Apache.

### [Cenário 2 - Diagnóstico e Auditoria de SQL Injection](./cenario-2)
Uma aplicação web completa (dashboard SPA com Flask, HTML5, Vanilla CSS e JS, com tema Âmbar/Laranja) voltada para a identificação de falhas de injeção de comandos SQL (SQL Injection):
- Varredura de parâmetros em requisições GET ativas utilizando payloads conhecidos.
- Rastreamento e parsing de formulários HTML (POST) com simulação de preenchimento e envio de cargas úteis SQLi.
- Detecção e classificação baseadas em assinaturas de erros de bancos de dados (MySQL, PostgreSQL, Oracle, SQLite, MSSQL).
- Consolidação e envio para o **Google Cloud Vertex AI (Gemini)** para geração de um parecer técnico estruturado e instruções de remediação seguras (Prepared Statements/PDO).

---

## Como Navegar

Cada cenário possui sua própria pasta com código-fonte estruturado e documentação detalhada. Para iniciar, acesse o diretório do cenário que deseja explorar:

- [Ir para a pasta do Cenário 1](./cenario-1)
- [Ir para a pasta do Cenário 2](./cenario-2)
