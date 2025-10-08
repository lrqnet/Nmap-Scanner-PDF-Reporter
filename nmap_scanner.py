import nmap
import fpdf
import sys
import argparse
import threading
import time
import itertools
from datetime import datetime
from fpdf.enums import XPos, YPos # NEW: Import for modern API calls

class PDFReport(fpdf.FPDF):
    """
    Custom PDF class to handle header and footer generation.
    """
    def header(self):
        # CHANGED: Using Helvetica (core font) to avoid warnings
        self.set_font('Helvetica', 'B', 12)
        # CHANGED: Using modern API for cell creation
        self.cell(0, 10, 'Nmap Scan Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        # CHANGED: Using modern API for cell creation
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def _animate_loading(stop_event: threading.Event):
    """
    Displays a spinner animation in the console.
    This function is intended for internal use.
    """
    for char in itertools.cycle(['|', '/', '-', '\\']):
        if stop_event.is_set():
            break
        sys.stdout.write(f'\r[*] Scanning... {char} ')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 20 + '\r')
    sys.stdout.flush()

def run_nmap_scan(target: str, tcp: bool, udp: bool, all_ports: bool) -> nmap.PortScanner:
    """
    Executes an Nmap scan on the specified target.
    """
    nm = nmap.PortScanner()

    # NEW: Dynamically build Nmap arguments based on flags
    scan_types = []
    if tcp:
        scan_types.append('-sS')
    if udp:
        scan_types.append('-sU')
    if not scan_types: # Default behavior if no flag is specified
        scan_types.extend(['-sS', '-sU'])

    base_args = ['-sV', '--open', '-T4']
    if all_ports:
        base_args.append('-p-') # Scan all ports

    final_args = ' '.join(scan_types + base_args)

    print(f"[*] Starting Nmap scan on '{target}' with args: '{final_args}'.")
    print("[*] This may take a long time, especially with --all-ports...")

    stop_event = threading.Event()
    animation_thread = threading.Thread(target=_animate_loading, args=(stop_event,))

    try:
        animation_thread.start()
        nm.scan(hosts=target, arguments=final_args)
    finally:
        if animation_thread.is_alive():
            stop_event.set()
            animation_thread.join()

    print("[+] Scan complete.")
    return nm

def generate_pdf_report(scan_data: nmap.PortScanner, target: str, filename: str):
    """
    Generates a PDF report with the Nmap scan results.
    """
    print(f"[*] Generating PDF report: {filename}")

    if not scan_data.all_hosts():
        print("[!] No hosts found in scan results. The target may be offline or blocking scans.")
        return

    host = scan_data.all_hosts()[0]
    pdf = PDFReport()
    pdf.add_page()

    pdf.set_font('Helvetica', 'B', 14)
    # CHANGED: Using modern API for cell creation
    pdf.cell(0, 10, f'Target: {target} ({host})', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if scan_data[host].hostname():
        pdf.cell(0, 10, f'Hostname: {scan_data[host].hostname()}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 10, f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 10, f'Nmap Command: {scan_data.command_line()}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(10)

    for proto in ['tcp', 'udp']:
        if proto not in scan_data[host]:
            continue

        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 10, f'Open {proto.upper()} Ports', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

        pdf.set_font('Courier', 'B', 10)
        pdf.cell(20, 7, 'Port', border=1)
        pdf.cell(30, 7, 'State', border=1)
        pdf.cell(40, 7, 'Service', border=1)
        pdf.cell(90, 7, 'Version', border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font('Courier', '', 10)
        ports = sorted(scan_data[host][proto].keys())
        for port in ports:
            port_info = scan_data[host][proto][port]
            state = port_info.get('state', 'N/A')
            service = port_info.get('name', 'N/A')
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            extra_info = port_info.get('extrainfo', '')
            full_version = f"{product} {version} {extra_info}".strip() or "N/A"

            pdf.cell(20, 7, str(port), border=1)
            pdf.cell(30, 7, state, border=1)
            pdf.cell(40, 7, service, border=1)
            pdf.multi_cell(90, 7, full_version, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(10)

    pdf.output(filename)
    print(f"[+] PDF report successfully created: '{filename}'")

def main():
    parser = argparse.ArgumentParser(
        description="A Python script to scan a target for open ports using Nmap and generate a PDF report.",
        epilog="Example: python3 nmap_scanner.py -t scanme.nmap.org -o report.pdf --tcp -p"
    )
    parser.add_argument("-t", "--target", required=True, help="The IP address or domain to scan.")
    parser.add_argument("-o", "--output", help="The name of the output PDF file. If not provided, a default name will be generated.")
    # NEW: Flags for scan type
    parser.add_argument("--tcp", action="store_true", help="Perform TCP scan only.")
    parser.add_argument("--udp", action="store_true", help="Perform UDP scan only.")
    parser.add_argument("-p", "--all-ports", action="store_true", help="Scan all 65535 ports (can be very slow).")

    args = parser.parse_args()

    if args.tcp and args.udp:
        print("[!] Cannot use --tcp and --udp flags simultaneously. To scan both, omit both flags.")
        sys.exit(1)

    target = args.target
    output_file = args.output

    if not output_file:
        safe_target_name = target.replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"nmap_report_{safe_target_name}_{timestamp}.pdf"

    try:
        scan_results = run_nmap_scan(target, args.tcp, args.udp, args.all_ports)
        generate_pdf_report(scan_results, target, output_file)
    except nmap.nmap.PortScannerError:
        print(f"\n[!] Nmap Error: Could not scan target '{target}'. Please ensure Nmap is installed and you have proper permissions.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()