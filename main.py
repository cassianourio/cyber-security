import os
import sys
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from scanner.ssl_scanner import run_ssl_scan, clean_hostname
from scanner.header_scanner import run_header_scan
from scanner.ai_agent import analyze_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="Scanner de Vulnerabilidades de Servidor Web")
    parser.add_argument("-t", "--target", required=True, help="Domínio alvo ou URL para análise (ex: google.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Porta HTTPS (padrão: 443)")
    
    args = parser.parse_args()
    target = args.target
    port = args.port
    
    clean_host = clean_hostname(target)
    
    print(f"* Alvo de Análise: {clean_host}:{port}")
    print(f"* Projeto GCP: {config.GCP_PROJECT} | Região: {config.GCP_LOCATION}\n")
    
    print("* Executando scans locais...")
    ssl_results = run_ssl_scan(clean_host, port)
    header_results = run_header_scan(clean_host)
    
    consolidated_scan = {
        "scan_timestamp": datetime.now().isoformat(),
        "target": {
            "input": target,
            "hostname": clean_host,
            "port": port
        },
        "ssl_tls_diagnostics": ssl_results,
        "http_header_diagnostics": header_results
    }
    
    print("\n* Enviando dados para o Agente de IA no Vertex AI...")
    ai_report = analyze_vulnerabilities(consolidated_scan)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"relatorio_{clean_host}_{timestamp}.md"
    report_path = config.REPORTS_DIR / report_filename
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(ai_report)
        
    print(f"\n* Diagnóstico Concluído com Sucesso!")
    print(f"* Relatório salvo em: {report_path.absolute()}")

if __name__ == "__main__":
    main()
