import socket
import sys

# Load vulnerabilities from vulnerabilities.db
def load_vulnerabilities():
    db = {}
    try:
        with open("vulnerabilities.db", "r") as file:
            for line in file:
                line = line.strip()
                if line.startswith("#") or line == "":
                    continue
                if "|" in line:
                    key, desc = line.split("|", 1)
                    db[key.strip()] = desc.strip()
    except FileNotFoundError:
        print("Error: vulnerabilities.db file not found!")
        sys.exit(1)
    return db


# Scan specific port
def scan_port(target, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return None


# Check banner with vulnerability database
def banner_vuln_check(banner, vuln_db):
    for key in vuln_db:
        if key in banner:
            return f"VULNERABLE → {vuln_db[key]}"
    return "Safe (No known vulnerabilities detected)."


# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    vuln_db = load_vulnerabilities()

    print(f"\n🔍 Starting Vulnerability Scan on {target}\n")

    # Common ports
    ports = [21, 22, 80, 443]

    for port in ports:
        print(f"Scanning port {port}...")
        banner = scan_port(target, port)

        if banner:
            print(f"[+] Banner: {banner}")
            result = banner_vuln_check(banner, vuln_db)
            print(f"[!] Result: {result}\n")
        else:
            print("[-] No banner detected or service hidden.\n")

    print("✔ Scan Completed!")


if __name__ == "__main__":
    main()
