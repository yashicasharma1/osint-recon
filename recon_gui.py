from database import init_db, save_scan, get_all_scans
import socket
import dns.resolver
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import whois

results = {
    "ip": "",
    "dns": [],
    "subdomains": [],
    "whois": "",
    "geo": ""
}


def log(widget, message):
    widget.insert(tk.END, message + "\n")
    widget.see(tk.END)


def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip
        log(overview_box, f"[+] IP Address: {ip}")
    except:
        log(overview_box, "[-] Unable to resolve IP address.")


def get_dns_records(domain):
    record_types = ['A', 'MX', 'TXT', 'NS']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                entry = f"{record}: {rdata}"
                results["dns"].append(entry)
                log(dns_box, entry)
        except:
            continue


def hackertarget_subdomains(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            log(subdomain_box, "[-] API error")
            return

        lines = response.text.split("\n")
        for line in lines:
            if "," in line:
                subdomain = line.split(",")[0]
                results["subdomains"].append(subdomain)
                log(subdomain_box, subdomain)
    except:
        log(subdomain_box, "[-] Subdomain lookup failed")


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        info = f"""
Registrar: {w.registrar}
Creation Date: {w.creation_date}
Expiration Date: {w.expiration_date}
Organization: {w.org}
"""
        results["whois"] = info
        log(whois_box, info)
    except:
        log(whois_box, "WHOIS lookup failed")


def geo_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        save_scan(domain, ip)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()

        info = f"""
Country: {data.get('country')}
City: {data.get('city')}
ISP: {data.get('isp')}
Organization: {data.get('org')}
"""
        results["geo"] = info
        log(geo_box, info)
    except:
        log(geo_box, "GeoIP lookup failed")

def calculate_risk():
    score = 0

    # Subdomain exposure
    if len(results["subdomains"]) > 20:
        score += 3
    elif len(results["subdomains"]) > 5:
        score += 2
    else:
        score += 1

    # DNS exposure
    if len(results["dns"]) > 10:
        score += 2

    # WHOIS missing
    if not results["whois"]:
        score += 2

    # Geo check
    if "United States" not in results["geo"]:
        score += 1

    # Final decision
    if score >= 6:
        return "HIGH RISK"
    elif score >= 3:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"
def run_recon():
    domain = domain_entry.get().strip()

    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return

    # Clear previous results
    for box in [overview_box, dns_box, subdomain_box, whois_box, geo_box]:
        box.delete(1.0, tk.END)

    results["dns"].clear()
    results["subdomains"].clear()

    status_label.config(text="Running intelligence gathering...")

    get_ip(domain)
    get_dns_records(domain)
    hackertarget_subdomains(domain)
    whois_lookup(domain)
    geo_lookup(domain)

    summary_label.config(
        text=f"Subdomains: {len(results['subdomains'])} | DNS Records: {len(results['dns'])}"
    )

    status_label.config(text="Recon completed ✔")
    risk = calculate_risk()
    log(overview_box, f"\n⚠ Risk Level: {risk}")


def start_thread():
    thread = threading.Thread(target=run_recon)
    thread.start()


# ---------------- GUI ---------------- #
init_db()
root = tk.Tk()
root.title("Attack Surface Intelligence Dashboard")
root.geometry("1100x750")
root.configure(bg="#0d1117")

title = tk.Label(
    root,
    text="Attack Surface Intelligence Dashboard",
    font=("Consolas", 20, "bold"),
    fg="#00ff9c",
    bg="#0d1117"
)
title.pack(pady=10)

domain_entry = tk.Entry(
    root,
    width=50,
    font=("Consolas", 12),
    bg="#161b22",
    fg="#00ff9c",
    insertbackground="white"
)
domain_entry.pack(pady=5)

tk.Button(
    root,
    text="Start Analysis",
    command=start_thread,
    bg="#00ff9c",
    fg="black",
    font=("Consolas", 11, "bold"),
    padx=10,
    pady=5
).pack(pady=10)

status_label = tk.Label(
    root,
    text="Idle",
    fg="white",
    bg="#0d1117",
    font=("Consolas", 10)
)
status_label.pack()

summary_label = tk.Label(
    root,
    text="Subdomains: 0 | DNS Records: 0",
    fg="#00ff9c",
    bg="#0d1117",
    font=("Consolas", 11)
)
summary_label.pack(pady=5)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both", padx=10, pady=10)

tabs = {}
for name in ["Overview", "DNS", "Subdomains", "WHOIS", "GeoIP"]:
    frame = tk.Frame(notebook, bg="#010409")
    notebook.add(frame, text=name)
    box = scrolledtext.ScrolledText(
        frame,
        bg="#010409",
        fg="#00ff9c",
        font=("Consolas", 10)
    )
    box.pack(expand=True, fill="both")
    tabs[name] = box
from database import init_db, save_scan, get_all_scans
import socket
import dns.resolver
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import whois

results = {
    "ip": "",
    "dns": [],
    "subdomains": [],
    "whois": "",
    "geo": ""
}


def log(widget, message):
    widget.insert(tk.END, message + "\n")
    widget.see(tk.END)


def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip
        log(overview_box, f"[+] IP Address: {ip}")
    except:
        log(overview_box, "[-] Unable to resolve IP address.")


def get_dns_records(domain):
    record_types = ['A', 'MX', 'TXT', 'NS']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                entry = f"{record}: {rdata}"
                results["dns"].append(entry)
                log(dns_box, entry)
        except:
            continue


def hackertarget_subdomains(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            log(subdomain_box, "[-] API error")
            return

        lines = response.text.split("\n")
        for line in lines:
            if "," in line:
                subdomain = line.split(",")[0]
                results["subdomains"].append(subdomain)
                log(subdomain_box, subdomain)
    except:
        log(subdomain_box, "[-] Subdomain lookup failed")


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        info = f"""
Registrar: {w.registrar}
Creation Date: {w.creation_date}
Expiration Date: {w.expiration_date}
Organization: {w.org}
"""
        results["whois"] = info
        log(whois_box, info)
    except:
        log(whois_box, "WHOIS lookup failed")


def geo_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        save_scan(domain, ip)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()

        info = f"""
Country: {data.get('country')}
City: {data.get('city')}
ISP: {data.get('isp')}
Organization: {data.get('org')}
"""
        results["geo"] = info
        log(geo_box, info)
    except:
        log(geo_box, "GeoIP lookup failed")


def run_recon():
    domain = domain_entry.get().strip()

    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return

    # Clear previous results
    for box in [overview_box, dns_box, subdomain_box, whois_box, geo_box]:
        box.delete(1.0, tk.END)

    results["dns"].clear()
    results["subdomains"].clear()

    status_label.config(text="Running intelligence gathering...")

    get_ip(domain)
    get_dns_records(domain)
    hackertarget_subdomains(domain)
    whois_lookup(domain)
    geo_lookup(domain)

    summary_label.config(
        text=f"Subdomains: {len(results['subdomains'])} | DNS Records: {len(results['dns'])}"
    )

    status_label.config(text="Recon completed ✔")


def start_thread():
    thread = threading.Thread(target=run_recon)
    thread.start()
def load_scan_history():
    history_box.delete(1.0, tk.END)
    scans = get_all_scans()

    for scan in scans:
        domain, ip, timestamp = scan
        history_box.insert(tk.END, f"{timestamp} | {domain} | {ip}\n")

# ---------------- GUI ---------------- #
init_db()
root = tk.Tk()
root.title("Attack Surface Intelligence Dashboard")
root.geometry("1100x750")
root.configure(bg="#0d1117")

title = tk.Label(
    root,
    text="Attack Surface Intelligence Dashboard",
    font=("Consolas", 20, "bold"),
    fg="#00ff9c",
    bg="#0d1117"
)
title.pack(pady=10)

domain_entry = tk.Entry(
    root,
    width=50,
    font=("Consolas", 12),
    bg="#161b22",
    fg="#00ff9c",
    insertbackground="white"
)
domain_entry.pack(pady=5)

tk.Button(
    root,
    text="Start Analysis",
    command=start_thread,
    bg="#00ff9c",
    fg="black",
    font=("Consolas", 11, "bold"),
    padx=10,
    pady=5
).pack(pady=10)

status_label = tk.Label(
    root,
    text="Idle",
    fg="white",
    bg="#0d1117",
    font=("Consolas", 10)
)
status_label.pack()

summary_label = tk.Label(
    root,
    text="Subdomains: 0 | DNS Records: 0",
    fg="#00ff9c",
    bg="#0d1117",
    font=("Consolas", 11)
)
summary_label.pack(pady=5)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both", padx=10, pady=10)

tabs = {}
for name in ["Overview", "DNS", "Subdomains", "WHOIS", "GeoIP"]:
    frame = tk.Frame(notebook, bg="#010409")
    notebook.add(frame, text=name)
    box = scrolledtext.ScrolledText(
        frame,
        bg="#010409",
        fg="#00ff9c",
        font=("Consolas", 10)
    )
    box.pack(expand=True, fill="both")
    tabs[name] = box

history_tab = tk.Frame(notebook, bg="#010409")
notebook.add(history_tab, text="Scan History")

history_box = scrolledtext.ScrolledText(
    history_tab,
    bg="#010409",
    fg="#00ff9c",
    font=("Consolas", 10)
)
history_box.pack(expand=True, fill="both")
overview_box = tabs["Overview"]
dns_box = tabs["DNS"]
subdomain_box = tabs["Subdomains"]
whois_box = tabs["WHOIS"]
geo_box = tabs["GeoIP"]
load_scan_history()
root.mainloop()