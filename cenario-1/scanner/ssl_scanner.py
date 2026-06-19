import ssl
import socket
import datetime
from urllib.parse import urlparse
from cryptography import x509

def clean_hostname(target):
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        parsed = urlparse(f'https://{target}')
    else:
        parsed = urlparse(target)
    
    hostname = parsed.hostname
    if not hostname:
        hostname = target.split('/')[0].split(':')[0]
    return hostname

def check_tls_support(hostname, port=443):
    tls_versions = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3
    }
    
    results = {}
    
    for name, version in tls_versions.items():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
        
        try:
            context.minimum_version = version
            context.maximum_version = version
        except AttributeError:
            results[name] = "Unknown/Unsupported by local system"
            continue
            
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated_version = ssock.version()
                    results[name] = {
                        "supported": True,
                        "negotiated_version": negotiated_version
                    }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            results[name] = {
                "supported": False,
                "error": str(e)
            }
            
    return results

def scan_ssl_certificate(hostname, port=443):
    try:
        pem_cert = ssl.get_server_certificate((hostname, port), timeout=5)
        cert = x509.load_pem_x509_certificate(pem_cert.encode('utf-8'))
        
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            
        now = datetime.datetime.now(datetime.timezone.utc)
        time_to_expire = not_after - now
        days_remaining = time_to_expire.days
        is_expired = days_remaining < 0
        
        sig_algo = cert.signature_algorithm_oid._name
        
        issuer = ", ".join([f"{attr.oid._name}={attr.value}" for attr in cert.issuer])
        subject = ", ".join([f"{attr.oid._name}={attr.value}" for attr in cert.subject])
        
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
            
        return {
            "success": True,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "signature_algorithm": sig_algo,
            "serial_number": str(cert.serial_number),
            "sans": sans
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def run_ssl_scan(target, port=443):
    hostname = clean_hostname(target)
    print(f"* Iniciando varredura SSL/TLS para {hostname}:{port}...")
    
    cert_info = scan_ssl_certificate(hostname, port)
    tls_info = check_tls_support(hostname, port)
    
    return {
        "hostname": hostname,
        "port": port,
        "certificate": cert_info,
        "tls_support": tls_info
    }
