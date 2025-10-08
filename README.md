# Nmap Scanner & PDF Reporter

A versatile and user-friendly Python script that utilizes Nmap to scan a target for open ports, then generates a clean and professional PDF report of the findings.

## Features

-   **Selectable Scan Types:** Easily choose between TCP-only, UDP-only, or a combined scan.
-   **Comprehensive Scanning:** Includes an option for a full scan across all 65,535 ports for maximum thoroughness.
-   **Service & Version Detection:** Identifies services and their versions running on open ports.
-   **Clean PDF Reporting:** Generates a professional, easy-to-read PDF report of the scan results.
-   **User-Friendly:** Provides real-time console feedback during the scan and flexible command-line arguments.

## Prerequisites

Before running the script, you need to have Python and Nmap installed on your system.

**1. Python 3**

Ensure you have Python 3 installed. You can check with `python3 --version`. It's highly recommended to run this project inside a Python virtual environment.

**2. Nmap**

Nmap is essential for this script to function.

-   **On Debian/Ubuntu:**
    ```bash
    sudo apt update && sudo apt install nmap
    ```
-   **On Red Hat/CentOS:**
    ```bash
    sudo yum install nmap
    ```
-   **On macOS (using Homebrew):**
    ```bash
    brew install nmap
    ```

**3. Python Libraries**

Install the required Python libraries using pip:

```bash
pip install python-nmap fpdf2
```

## Usage

1.  Clone the repository or download the `nmap_scanner.py` script.
2.  Open your terminal and navigate to the script's directory. (Activate your virtual environment if you are using one).
3.  Run the script using the following command structure:

```bash
python3 nmap_scanner.py --target <IP_OR_DOMAIN> [options]
```

### Options

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-t` | `--target` | **(Required)** The IP address or domain name to scan. |
| `-o` | `--output` | **(Optional)** The name for the output PDF file. If omitted, a default name is generated. |
| | `--tcp` | **(Optional)** Performs a TCP scan only. Cannot be used with `--udp`. |
| | `--udp` | **(Optional)** Performs a UDP scan only. Cannot be used with `--tcp`. |
| `-p` | `--all-ports` | **(Optional)** Scans all 65,535 ports instead of just the common ones. **Warning:** This can be very slow. |

_Note: If neither `--tcp` nor `--udp` is specified, the script defaults to scanning both._

### Examples

**1. Default Scan (TCP & UDP, common ports)**
```bash
python3 nmap_scanner.py -t scanme.nmap.org
```

**2. TCP-Only Scan (common ports)**
```bash
python3 nmap_scanner.py -t scanme.nmap.org --tcp
```

**3. UDP-Only Scan with a Custom Output File**
```bash
python3 nmap_scanner.py -t 192.168.1.1 --udp -o My_UDP_Report.pdf
```

**4. Complete TCP Scan of All Ports (slower)**
```bash
python3 nmap_scanner.py -t example.com --tcp -p
```
_This will scan all 65,535 TCP ports on `example.com`._

**5. Complete Scan of Both TCP & UDP (very slow)**
```bash
python3 nmap_scanner.py -t example.com -p -o full_scan_report.pdf
```

## Disclaimer

⚠️ **This tool is intended for educational purposes and for use in authorized security assessments only.** Performing scans on networks and systems without explicit permission from the owner is illegal in many jurisdictions. The author is not responsible for any misuse or damage caused by this script. Use it responsibly.

---
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/lrqnet)
