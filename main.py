import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Add the project directory to python path if run from elsewhere
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Force standard streams to use UTF-8 on Windows to prevent UnicodeEncodeError with emojis/block symbols
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding='utf-8')

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

import config
from scanner.ssl_scanner import run_ssl_scan, clean_hostname
from scanner.header_scanner import run_header_scan
from scanner.ai_agent import analyze_vulnerabilities

console = Console()

def print_banner():
    banner_text = """
  [bold red]██████[/bold red]  [bold yellow]██   ██[/bold yellow] [bold green]██████[/bold green]  [bold blue]██████[/bold blue]  [bold magenta]███████[/bold magenta] [bold cyan]███████[/bold cyan]  [bold white]██████[/bold white]
 [bold red]██[/bold red]       [bold yellow]██   ██[/bold yellow] [bold green]██   ██[/bold green] [bold blue]██   ██[/bold blue] [bold magenta]██[/bold magenta]      [bold cyan]██[/bold cyan]       [bold white]██[/bold white]
 [bold red]██[/bold red]        [bold yellow]█████[/bold yellow]  [bold green]██████[/bold green]  [bold blue]██████[/bold blue]  [bold magenta]█████[/bold magenta]   [bold cyan]███████[/bold cyan] [bold white]██[/bold white]
 [bold red]██[/bold red]          [bold yellow]██[/bold yellow]    [bold green]██   ██[/bold green] [bold blue]██   ██[/bold blue] [bold magenta]██[/bold magenta]           [bold cyan]██[/bold cyan] [bold white]██[/bold white]
  [bold red]██████[/bold red]     [bold yellow]██[/bold yellow]    [bold green]██████[/bold green]  [bold blue]██   ██[/bold blue] [bold magenta]███████[/bold magenta] [bold cyan]███████[/bold cyan]  [bold white]██████[/bold white]
                                                              
[bold green]✦ Ferramenta de Diagnóstico Automatizado de Vulnerabilidades (Cenário 1) ✦[/bold green]
"""
    console.print(Panel(banner_text, border_style="cyan", subtitle="Projeto de Segurança III"))

def display_local_results(ssl_res, header_res):
    """
    Renders the collected local scan data into clean, readable Rich tables.
    """
    console.print("\n[bold cyan]🔍 Resumo dos Dados Coletados Localmente:[/bold cyan]\n")
    
    # 1. SSL/TLS and Certificate Table
    cert = ssl_res.get("certificate", {})
    tls = ssl_res.get("tls_support", {})
    
    cert_table = Table(title="Informações de Certificado & TLS", show_header=True, header_style="bold magenta")
    cert_table.add_column("Propriedade", style="cyan")
    cert_table.add_column("Status / Valor", style="white")
    
    if cert.get("success"):
        cert_table.add_row("Emissor", cert.get("issuer")[:80] + "...")
        days = cert.get("days_remaining", 0)
        day_color = "green" if days > 30 else ("yellow" if days > 0 else "red")
        cert_table.add_row("Validade", f"[{day_color}]{days} dias restantes (Expira em: {cert.get('not_after')[:10]})[/{day_color}]")
        cert_table.add_row("Algoritmo de Assinatura", cert.get("signature_algorithm"))
    else:
        cert_table.add_row("Erro de Certificado", f"[red]{cert.get('error')}[/red]")
        
    for tls_ver, state in tls.items():
        if isinstance(state, dict):
            supported = state.get("supported", False)
            status_text = "[green]Habilitado[/green]" if supported else "[red]Desabilitado[/red]"
            if tls_ver in ["TLSv1.0", "TLSv1.1"] and supported:
                status_text += " [bold yellow]⚠️ (Inseguro)[/bold yellow]"
            cert_table.add_row(tls_ver, status_text)
        else:
            cert_table.add_row(tls_ver, f"[yellow]{state}[/yellow]")
            
    console.print(cert_table)
    console.print()

    # 2. HTTP Headers Table
    headers_scan = header_res.get("headers_scan", {})
    
    headers_table = Table(title="Status de Cabeçalhos HTTP de Segurança", show_header=True, header_style="bold blue")
    headers_table.add_column("Protocolo", style="cyan")
    headers_table.add_column("Status de Acesso", style="white")
    headers_table.add_column("Cabeçalhos de Segurança Presentes", style="green")
    headers_table.add_column("Cabeçalhos Inseguros / Ausentes", style="red")
    
    for scheme, info in headers_scan.items():
        if "error" in info:
            headers_table.add_row(scheme.upper(), f"[red]Inacessível: {info['error'][:50]}[/red]", "-", "-")
            continue
            
        status = f"Disponível (HTTP {info.get('status_code')})"
        if info.get("redirect_to"):
            status += f"\n-> Redireciona para {info.get('redirect_to')[:30]}..."
            
        present = "\n".join(info.get("headers_found", {}).keys()) or "Nenhum"
        missing = "\n".join(info.get("missing_security_headers", [])) or "Nenhum"
        
        # Disclosure server check
        disclosures = info.get("server_disclosure", {})
        if disclosures:
            missing += "\n[Server Banner Leak]:\n" + "\n".join([f"{k}: {v}" for k, v in disclosures.items()])
            
        headers_table.add_row(scheme.upper(), status, present, missing)
        
    console.print(headers_table)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Scanner de Vulnerabilidades de Servidor Web (Cenário 1)")
    parser.add_argument("-t", "--target", required=True, help="Domínio alvo ou URL para análise (ex: google.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Porta HTTPS (padrão: 443)")
    
    args = parser.parse_args()
    target = args.target
    port = args.port
    
    clean_host = clean_hostname(target)
    
    console.print(f"[bold green][+][/bold green] Alvo de Análise: [bold white]{clean_host}:{port}[/bold white]")
    console.print(f"[bold green][+][/bold green] Projeto GCP: [bold white]{config.GCP_PROJECT}[/bold white] | Região: [bold white]{config.GCP_LOCATION}[/bold white]\n")
    
    # 1. Execute local scans
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Realizando handshakes SSL/TLS...", total=None)
        ssl_results = run_ssl_scan(clean_host, port)
        
        progress.add_task(description="Verificando cabeçalhos HTTP...", total=None)
        header_results = run_header_scan(clean_host)
        
    # 2. Display local scanning tables
    display_local_results(ssl_results, header_results)
    
    # 3. Consolidate results for AI agent
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
    
    # 4. Invoke AI agent via Vertex AI
    console.print("\n[bold yellow][*] Enviando dados para o Agente de IA no Vertex AI...[/bold yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Gemini analisando vulnerabilidades...", total=None)
        ai_report = analyze_vulnerabilities(consolidated_scan)
        
    # 5. Save report to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"relatorio_{clean_host}_{timestamp}.md"
    report_path = config.REPORTS_DIR / report_filename
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(ai_report)
        
    console.print("\n[bold green]✓ Diagnóstico Concluído com Sucesso![/bold green]")
    console.print(Panel(
        f"O relatório de auditoria gerado pelo Gemini foi salvo em:\n[bold cyan]{report_path.absolute()}[/bold cyan]\n\nVocê pode abrir este arquivo Markdown para ler o diagnóstico completo e as recomendações de mitigação.",
        title="[bold green]Relatório Salvo[/bold green]",
        border_style="green"
    ))

if __name__ == "__main__":
    main()
