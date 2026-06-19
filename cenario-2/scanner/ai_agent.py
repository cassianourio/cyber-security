import json
import vertexai
from vertexai.generative_models import GenerativeModel
import config
from scanner.prompts import SQLI_AUDIT_PROMPT

def analyze_vulnerabilities(scan_data):
    print(f"* Inicializando o agente de IA Vertex AI ({config.GEMINI_MODEL}) para diagnóstico de banco de dados...")
    
    vertexai.init(project=config.GCP_PROJECT, location=config.GCP_LOCATION)
    model = GenerativeModel(config.GEMINI_MODEL)
    formatted_data = json.dumps(scan_data, indent=2, ensure_ascii=False)
    
    prompt = SQLI_AUDIT_PROMPT.format(formatted_data=formatted_data)

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"* Erro ao chamar a API do Vertex AI: {e}")
        return f"# Erro no Diagnóstico\nOcorreu um erro ao processar os dados com o Gemini: {e}"
