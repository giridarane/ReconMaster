import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar
import requests

# Helper functions
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return e.output

def save_result(directory, filename, content):
    filepath = os.path.join(directory, filename)
    with open(filepath, "w") as file:
        file.write(content)

# Define all the required functions

def domain_information(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Fetching WHOIS Information...\n", "green")
    root.update()
    whois_result = run_command(f"whois {domain}")
    save_result(directory, "whois_lookup.txt", whois_result)
    log_text.insert(tk.END, whois_result + "\n", "green")

    log_text.insert(tk.END, "[INFO] Retrieving DNS Records...\n", "green")
    root.update()
    dns_result = run_command(f"dig {domain} ANY +noall +answer")
    save_result(directory, "dns_info.txt", dns_result)
    log_text.insert(tk.END, dns_result + "\n", "green")

def server_information(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Fetching HTTP Headers...\n", "green")
    root.update()
    headers_result = run_command(f"curl -I {domain}")
    save_result(directory, "http_headers.txt", headers_result)
    log_text.insert(tk.END, headers_result + "\n", "green")

    log_text.insert(tk.END, "[INFO] Checking SSL/TLS Certificate...\n", "green")
    root.update()
    ssl_result = run_command(f"testssl.sh {domain}")
    save_result(directory, "ssl_info.txt", ssl_result)
    log_text.insert(tk.END, ssl_result + "\n", "green")

def technology_stack(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Detecting Technology Stack...\n", "green")
    root.update()
    tech_result = run_command(f"whatweb {domain}")
    save_result(directory, "technology_stack.txt", tech_result)
    log_text.insert(tk.END, tech_result + "\n", "green")

def publicly_available_info(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Gathering Publicly Available Information...\n", "green")
    root.update()
    osint_result = run_command(f"theHarvester -d {domain} -b all")
    save_result(directory, "osint_info.txt", osint_result)
    log_text.insert(tk.END, osint_result + "\n", "green")

def subdomain_enumeration(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Enumerating Subdomains with Amass and Sublist3r...\n", "green")
    root.update()
    amass_result = run_command(f"amass enum -d {domain}")
    save_result(directory, "amass_subdomains.txt", amass_result)
    log_text.insert(tk.END, amass_result + "\n", "green")
    
    sublist3r_result = run_command(f"sublist3r -d {domain}")
    save_result(directory, "sublist3r_subdomains.txt", sublist3r_result)
    log_text.insert(tk.END, sublist3r_result + "\n", "green")

def nmap_scan(ip, directory):
    log_text.insert(tk.END, "\n[INFO] Running Nmap scan for open ports...\n", "green")
    root.update()
    nmap_result = run_command(f"nmap -sV {ip}")
    save_result(directory, "nmap_scan.txt", nmap_result)
    log_text.insert(tk.END, nmap_result + "\n", "green")

def shodan_scan(ip, directory):
    log_text.insert(tk.END, "\n[INFO] Searching Shodan for exposed services...\n", "green")
    root.update()
    # Ensure you have a valid Shodan API key
    api_key = "your_shodan_api_key"
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        result = response.json()
        save_result(directory, "shodan_info.txt", str(result))
        log_text.insert(tk.END, f"Shodan Results: {str(result)}\n", "green")
    else:
        log_text.insert(tk.END, "[ERROR] Shodan API request failed.\n", "red")

def google_dorking(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Performing Google Dorking search...\n", "green")
    root.update()
    dork_results = run_command(f"google dork 'site:{domain}'")
    save_result(directory, "google_dorking.txt", dork_results)
    log_text.insert(tk.END, dork_results + "\n", "green")

def directory_fuzzing(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Running Directory Fuzzing with Dirb...\n", "green")
    root.update()
    dirb_result = run_command(f"dirb http://{domain}")
    save_result(directory, "dirb_scan.txt", dirb_result)
    log_text.insert(tk.END, dirb_result + "\n", "green")

def ssl_scan(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Running SSL/TLS Security Scan...\n", "green")
    root.update()
    ssl_result = run_command(f"testssl.sh {domain}")
    save_result(directory, "ssl_scan.txt", ssl_result)
    log_text.insert(tk.END, ssl_result + "\n", "green")

def technology_stack(domain, directory):
    log_text.insert(tk.END, "\n[INFO] Detecting Technology Stack with Wappalyzer...\n", "green")
    root.update()
    tech_result = run_command(f"wappalyzer {domain}")
    save_result(directory, "technology_stack.txt", tech_result)
    log_text.insert(tk.END, tech_result + "\n", "green")

# GUI Setup
def start_audit():
    domain = domain_entry.get().replace("http://", "").replace("https://", "")
    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return

    directory = os.path.join(os.getcwd(), directory_entry.get())
    os.makedirs(directory, exist_ok=True)

    log_text.insert(tk.END, f"\n[INFO] Starting audit for {domain}...\n", "green")

    # Run all reconnaissance steps
    domain_information(domain, directory)
    server_information(domain, directory)
    technology_stack(domain, directory)
    publicly_available_info(domain, directory)
    subdomain_enumeration(domain, directory)
    nmap_scan(domain, directory)
    shodan_scan(domain, directory)
    google_dorking(domain, directory)
    directory_fuzzing(domain, directory)
    ssl_scan(domain, directory)

    log_text.insert(tk.END, "\n[INFO] Audit completed. Results saved.", "green")
    messagebox.showinfo("Success", f"Audit completed for {domain}. Results saved in {directory}.")

root = tk.Tk()
root.title("Advanced Website Audit Tool")
root.geometry("800x600")
root.resizable(True, True)
root.configure(bg="black")

frame = tk.Frame(root, bg="black")
frame.pack(padx=10, pady=10)

domain_label = tk.Label(frame, text="Enter Domain:", fg="green", bg="black")
domain_label.grid(row=0, column=0, padx=5, pady=5)

domain_entry = tk.Entry(frame, width=40, bg="black", fg="green", insertbackground="green")
domain_entry.grid(row=0, column=1, padx=5, pady=5)

directory_label = tk.Label(frame, text="Enter Directory Name:", fg="green", bg="black")
directory_label.grid(row=1, column=0, padx=5, pady=5)

directory_entry = tk.Entry(frame, width=40, bg="black", fg="green", insertbackground="green")
directory_entry.grid(row=1, column=1, padx=5, pady=5)

start_button = tk.Button(frame, text="Start Audit", command=start_audit, bg="green", fg="black")
start_button.grid(row=0, column=2, padx=5, pady=5)

log_frame = tk.LabelFrame(root, text="Logs", fg="green", bg="black")
log_frame.pack(padx=10, pady=10, fill="both", expand=True)

scrollbar = Scrollbar(log_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

log_text = tk.Text(log_frame, height=20, width=100, bg="black", fg="green", insertbackground="green", yscrollcommand=scrollbar.set)
log_text.pack(padx=10, pady=10, fill="both", expand=True)
scrollbar.config(command=log_text.yview)

log_text.tag_config("green", foreground="green")

root.mainloop()
