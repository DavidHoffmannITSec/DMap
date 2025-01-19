import ipaddress
import socket
from urllib.parse import urlparse
import sys
from ssl import create_default_context, SSLError
from concurrent.futures import ThreadPoolExecutor
import requests
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1
import time
from config import protocols


# TCP/IP Fingerprinting using Scapy for Advanced OS Detection
def tcp_fingerprint(ip, port=80):
    try:
        response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=2, verbose=False)
        if response:
            ttl = response.ttl
            window_size = response.getlayer(TCP).window
            options = response.getlayer(TCP).options

            # Analyze TCP Options for OS Detection
            option_set = {opt[0]: opt[1] for opt in options}

            # Use common patterns to infer OS
            if ttl <= 64:
                os_detected = "Linux/Unix-based"
            elif ttl <= 128:
                os_detected = "Windows"
            else:
                os_detected = "Unknown OS"

            if "Timestamp" in option_set:
                os_detected += " (Supports TCP Timestamps)"

            if "MSS" in option_set:
                mss_value = option_set["MSS"]
                if mss_value in [1460, 1464]:
                    os_detected += " - Possibly Linux"
                elif mss_value in [1380, 1360]:
                    os_detected += " - Possibly macOS"

            if "Window Scale" in option_set:
                window_scale = option_set["Window Scale"]
                if window_scale == 8:
                    os_detected += " - Modern Windows Version"

            return f"Detected OS: {os_detected} (TTL={ttl}, Window Size={window_size})"
        else:
            return "No response"
    except Exception as e:
        return f"Error: {e}"

# Service and Version Detection
def service_version_detection(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024).decode().strip()
            if response:
                return response
            return "Unknown version"
    except Exception as e:
        return f"Error: {e}"

# Banner Grabbing with SSL Certificate Extraction
def banner_grabbing(ip, port):
    try:
        context = create_default_context()
        with socket.create_connection((ip, port), timeout=2) as sock:
            if port == 443:
                with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                    cert = tls_sock.getpeercert()
                    banner = tls_sock.recv(1024).decode().strip()
                    cert_info = {
                        "issuer": cert.get("issuer"),
                        "subject": cert.get("subject"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter")
                    }
                    return banner, cert_info
            else:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode().strip()
                return banner, None
    except (SSLError, socket.error) as e:
        return None, None

# Reverse DNS and Domain Lookup
def reverse_dns(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return f"PTR Record: {host}"
    except socket.herror:
        return "No PTR record"

# Directory Scanning for Web Servers with Custom List and Multithreading
def directory_scanning(ip, port, custom_directories=None):
    directories = custom_directories if custom_directories else ["/admin", "/login", "/dashboard", "/config"]
    open_dirs = []

    def scan_directory(dir):
        try:
            url = f"http://{ip}:{port}{dir}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                open_dirs.append(url)
        except requests.exceptions.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_directory, directories)

    return open_dirs

# Real-Time Detection of Firewalls and IDS/IPS with Timing Analysis
def detect_firewall(ip):
    try:
        start_time = time.time()
        response = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=2, verbose=False)
        end_time = time.time()
        if not response:
            return "Possible firewall detected (no response)"
        elif response.getlayer(TCP).flags == "RA":
            return "Firewall or IDS detected (RST/ACK response)"
        elif end_time - start_time > 1:
            return "Firewall detected: Slow response indicates rate limiting"
        return "No firewall detected"
    except Exception as e:
        return f"Error detecting firewall: {e}"


# Helper Function to Resolve Domain, Subnet, or IP Range to a List of IPs
def resolve_targets(target):
    ip_list = []
    try:
        # 1. Entferne das Schema (http/https) aus der URL, falls vorhanden
        if target.startswith("http://") or target.startswith("https://"):
            parsed_url = urlparse(target)
            target = parsed_url.netloc  # Extrahiere die Domain

        # 2. Prüfe, ob Ziel eine gültige IP-Adresse ist
        try:
            ip = ipaddress.ip_address(target)
            ip_list.append(str(ip))
            print(f"Einzel-IP erkannt: {ip}")
            return ip_list  # IP-Adresse gefunden, Rückgabe
        except ValueError:
            pass  # Ziel ist keine IP, weiter prüfen

        # 3. Prüfe, ob Ziel eine Domain ist und löse sie auf
        try:
            resolved_ip = socket.gethostbyname(target)
            ip_list.append(resolved_ip)
            print(f"Domain aufgelöst: {target} -> {resolved_ip}")
        except socket.gaierror as e:
            print(f"Fehler beim Auflösen der Domain {target}: {e}")
    except Exception as e:
        print(f"Allgemeiner Fehler beim Verarbeiten des Ziels {target}: {e}")

    return ip_list

# Progress Display
def show_progress(current, total):
    progress = (current / total) * 100
    sys.stdout.write(f"\rProgress: {progress:.2f}% ({current}/{total} ports scanned)")
    sys.stdout.flush()

# Port Scanning Function
def port_scan(ip, port, scan_type, timeout, report_path):
    try:
        protocol = protocols.get(port, "Unknown")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                result = {"port": port, "status": "open", "protocol": protocol}
                if report_path:
                    write_report(f"Port: {port:<6} [open] {protocol}", report_path)
                return result
            else:
                return {"port": port, "status": "closed"}
    except Exception as e:
        # Fehler behandeln und zurückgeben
        return {"port": port, "status": "error", "error": str(e)}


# Function to Write Report to File
def write_report(data, report_path):
    if report_path:
        with open(report_path, "a") as f:
            f.write(data + "\n")
