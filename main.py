import threading
from queue import Queue
import argparse
from concurrent.futures import ThreadPoolExecutor
from config import aggression_levels, top_100_ports
from help import display_help
from scan import resolve_targets, port_scan, show_progress

# CVE Cache
cve_cache = {}

# Worker Function for Multithreading
def worker(scan_types, timeout, report_path, total_ports):
    scanned_ports = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        while not queue.empty():
            ip, port = queue.get()
            executor.submit(port_scan, ip, port, scan_types, timeout, report_path)
            scanned_ports += 1
            show_progress(scanned_ports, total_ports)
            queue.task_done()

# Main Function
def main():
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

    args = parser.parse_args()

    if args.help:
        display_help()
        return

    scan_types = args.scan_types if args.scan_types else ["TCP"]
    timeout = aggression_levels.get(args.t, 2)
    report_path = args.o

    if args.p:
        ports_to_scan = [int(p) for p in args.p.split(",")]
    else:
        ports_to_scan = top_100_ports if args.top else range(1, 65536)

    for target in args.targets:
        ip_list = resolve_targets(target)
        for ip in ip_list:
            for port in ports_to_scan:
                queue.put((ip, port))

    thread_list = []
    for _ in range(args.mt):
        t = threading.Thread(target=worker, args=(scan_types, timeout, report_path, len(ip_list) * len(ports_to_scan)))
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()

    print("\nScan completed.")


# Queue for multithreading
queue = Queue()

if __name__ == "__main__":
    main()