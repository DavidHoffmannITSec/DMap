# Function to display the help menu
def display_help():
    help_text = """
Advanced Port Scanner - Help Menu

Usage: python advanced_port_scanner.py [TARGETS] [OPTIONS]

Targets:
  - Single IP: 192.168.1.1
  - Domain: example.com
  - Subnet (CIDR): 192.168.1.0/24
  - IP Range: 192.168.1.1-192.168.1.254

Options:
  -sT       Perform a TCP scan
  -sU       Perform a UDP scan
  -sS       Perform a SYN scan
  -sX       Perform an XMAS scan
  -sF       Perform a FIN scan
  -sN       Perform a NULL scan
  -sV       Perform a Version scan (detect service versions)
  -t        Set aggression level (T0-T5)
  -p        Specify ports to scan (e.g., -p 80 or -p 80,443,21)
  -mt       Set number of threads for multithreading
  -top      Scan top 100 ports
  -r        Specify port range to scan
  -o        Path to save the report
  -help     Display this help menu
"""
    print(help_text)