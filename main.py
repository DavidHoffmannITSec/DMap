import argparse
from concurrent.futures import as_completed
from config import aggression_levels, top_100_ports
from help import display_help
from scan import *

# CVE-Cache global initialisieren
cve_cache = {}

# Argumente parsen
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("targets", nargs='+', help="Target IP addresses, domains, subnets, or ranges")
    parser.add_argument("-sT", action="append_const", const="TCP", dest="scan_types", help="Perform TCP scan")
    parser.add_argument("-sU", action="append_const", const="UDP", dest="scan_types", help="Perform UDP scan")
    parser.add_argument("-sS", action="append_const", const="SYN", dest="scan_types", help="Perform SYN scan")
    parser.add_argument("-sX", action="append_const", const="XMAS", dest="scan_types", help="Perform XMAS scan")
    parser.add_argument("-sF", action="append_const", const="FIN", dest="scan_types", help="Perform FIN scan")
    parser.add_argument("-sN", action="append_const", const="NULL", dest="scan_types", help="Perform NULL scan")
    parser.add_argument("-sV", action="append_const", const="Version", dest="scan_types", help="Perform Version scan (detect service versions)")
    parser.add_argument("-t", choices=aggression_levels.keys(), default="T3", help="Set aggression level (T0-T5)")
    parser.add_argument("-p", type=str, help="Specify ports to scan (e.g., -p 80 or -p 80,443,21)")
    parser.add_argument("-mt", type=int, default=10, help="Set number of threads for multithreading")
    parser.add_argument("-top", action="store_true", help="Scan top 100 ports")
    parser.add_argument("-r", nargs=2, type=int, metavar=("START", "END"), help="Port range to scan")
    parser.add_argument("-o", help="Path to save the report")
    parser.add_argument("-help", action="store_true", help="Display this help menu")
    return parser.parse_args()

# Ports basierend auf Argumenten auswählen
def get_ports_to_scan(args):
    if args.p:
        return [int(p) for p in args.p.split(",")]
    elif args.top:
        return top_100_ports
    elif args.r:
        return range(args.r[0], args.r[1] + 1)
    else:
        return range(1, 65536)

# Ziele auflösen
def resolve_all_targets(targets):
    all_ips = []
    for target in targets:
        ips = resolve_targets(target)
        if not ips:
            print(f"Error resolving target: {target}")
        else:
            all_ips.extend(ips)
    return all_ips

# Scans ausführen
def run_scans(ip_list, ports_to_scan, scan_types, timeout, report_path, max_threads):
    futures = {}
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip in ip_list:
            for port in ports_to_scan:
                future = executor.submit(port_scan, ip, port, scan_types, timeout, report_path)
                futures[future] = port

        print("\nScanning Results:\n")
        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result["status"] == "open":
                    protocol = result["protocol"]
                    open_ports.append(f"Port: {port} [open] ({protocol})")
                    print(Fore.GREEN + f"Port: {port:<6} [open] {protocol}" + Style.RESET_ALL)
                elif result["status"] == "closed":
                    print(Fore.RED + f"Port: {port:<6} [closed]" + Style.RESET_ALL)
                elif result["status"] == "error":
                    print(f"[Error scanning port {port}]: {result['error']}")
            except Exception as e:
                print(f"[Error scanning port {port}]: {e}")

    return open_ports


# Ergebnisse anzeigen
def display_results(open_ports):
    print("\n\nScan abgeschlossen.")
    if open_ports:
        print("\nGefundene offene Ports:")
        for port_info in open_ports:
            port_info = port_info.replace("[open]", Fore.GREEN + "[open]" + Style.RESET_ALL)
            print(port_info)
    else:
        print("\nKeine offenen Ports gefunden.")


# Hauptfunktion
def main():
    args = parse_arguments()

    if args.help:
        display_help()
        return

    scan_types = args.scan_types if args.scan_types else ["TCP"]
    timeout = aggression_levels.get(args.t, 2)
    report_path = args.o
    max_threads = args.mt

    ports_to_scan = get_ports_to_scan(args)
    ip_list = resolve_all_targets(args.targets)

    if not ip_list:
        print("Keine gültigen Ziele gefunden.")
        return

    open_ports = run_scans(ip_list, ports_to_scan, scan_types, timeout, report_path, max_threads)
    display_results(open_ports)

# Programm starten
if __name__ == "__main__":
    main()
