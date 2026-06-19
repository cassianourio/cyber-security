import ssl
import socket
import datetime
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def clean_hostname(target):
    """
    Cleans target input (which can be a URL or a hostname) to extract a clean hostname.
    """
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        # Add a dummy scheme to allow urlparse to process it correctly
        parsed = urlparse(f'https://{target}')
    else:
        parsed = urlparse(target)
    
    hostname = parsed.hostname
    if not hostname:
        # Fallback split if urlparse fails
        hostname = target.split('/')[0].split(':')[0]
    return hostname

def check_tls_support(hostname, port=443):
    """
    Checks which TLS versions (1.0, 1.1, 1.2, 1.3) are supported by the server.
    """
    tls_versions = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3
    }
    
    results = {}
    
    for name, version in tls_versions.items():
        # Create a connection context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
        
        # Restrict to only the target version
        try:
            context.minimum_version = version
            context.maximum_version = version
        except AttributeError:
            # Some python builds might disable TLS 1.0/1.1 constants
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
    """
    Connects to the host, retrieves the SSL certificate, and parses its fields.
    """
    try:
        # Get server certificate in PEM format
        pem_cert = ssl.get_server_certificate((hostname, port), timeout=5)
        # Parse certificate using cryptography
        cert = x509.load_pem_x509_certificate(pem_cert.encode('utf-8'))
        
        # Date extraction
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            # Compatibility with older cryptography versions
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            
        now = datetime.datetime.now(datetime.timezone.utc)
        time_to_expire = not_after - now
        days_remaining = time_to_expire.days
        is_expired = days_remaining < 0
        
        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name
        
        # Issuer and Subject parsing
        issuer = ", ".join([f"{attr.oid._name}={attr.value}" for attr in cert.issuer])
        subject = ", ".join([f"{attr.oid._name}={attr.value}" for attr in cert.subject])
        
        # Subject Alternative Names (SANs)
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
    """
    Runs both the TLS support and Certificate checks, consolidating the results.
    """
    hostname = clean_hostname(target)
    print(f"[*] Iniciando varredura SSL/TLS para {hostname}:{port}...")
    
    cert_info = scan_ssl_certificate(hostname, port)
    tls_info = check_tls_support(hostname, port)
    
    return {
        "hostname": hostname,
        "port": port,
        "certificate": cert_info,
        "tls_support": tls_info
    }
