import socket
import dns.resolver
import requests
import argparse

# store all results
results = []


def save_line(line):
    print(line)
    results.append(line)


def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        save_line(f"\n[+] IP Address: {ip}")
    except socket.gaierror:
        save_line("[-] Unable to resolve IP address.")


def get_dns_records(domain):
    save_line("\n[+] DNS Records:")
    record_types = ['A', 'MX', 'TXT', 'NS']

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                save_line(f"{record}: {rdata}")
        except:
            continue


def find_subdomains(domain):
    save_line("\n[+] Checking common subdomains...")

    subdomains = ["www", "mail", "ftp", "dev", "test", "admin"]

    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            save_line(f"[Basic] {subdomain}")
        except:
            pass


def crtsh_subdomains(domain):
    save_line("\n[+] Fetching real subdomains from crt.sh...")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            save_line(f"[-] crt.sh returned status code: {response.status_code}")
            return

        data = response.json()
        found = set()

        for entry in data:
            name = entry.get("name_value")
            if name:
                subs = name.split("\n")
                for sub in subs:
                    if domain in sub:
                        found.add(sub.strip())

        for sub in sorted(found):
            save_line(f"[crt.sh] {sub}")

    except requests.exceptions.RequestException as e:
        save_line(f"[-] crt.sh error: {e}")


def hackertarget_subdomains(domain):
    save_line("\n[+] Fetching subdomains from Hackertarget API...")

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            save_line("[-] Hackertarget API error")
            return

        lines = response.text.split("\n")

        for line in lines:
            if "," in line:
                subdomain = line.split(",")[0]
                save_line(f"[Hackertarget] {subdomain}")

    except Exception as e:
        save_line(f"[-] Hackertarget error: {e}")


def threatcrowd_subdomains(domain):
    save_line("\n[+] Fetching subdomains from ThreatCrowd...")

    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            save_line("[-] ThreatCrowd request failed")
            return

        data = response.json()
        subs = data.get("subdomains", [])

        for sub in subs:
            save_line(f"[ThreatCrowd] {sub}")

    except Exception as e:
        save_line(f"[-] ThreatCrowd error: {e}")


def save_report(domain):
    filename = f"{domain}_recon_report.txt"
    with open(filename, "w") as f:
        for line in results:
            f.write(line + "\n")

    print(f"\n[+] Report saved as {filename}")


def main():
    parser = argparse.ArgumentParser(description="OSINT Recon Tool")
    parser.add_argument("domain", help="Target domain (example: tesla.com)")
    args = parser.parse_args()

    domain = args.domain

    print("\nStarting Recon on:", domain)

    get_ip(domain)
    get_dns_records(domain)
    find_subdomains(domain)
    crtsh_subdomains(domain)
    hackertarget_subdomains(domain)
    threatcrowd_subdomains(domain)

    save_report(domain)


if __name__ == "__main__":
    main()