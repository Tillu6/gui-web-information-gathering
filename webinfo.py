import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import socket
import whois
import ipaddress
import requests
from bs4 import BeautifulSoup
import dns.resolver
from PIL import Image, ImageTk  # For image handling

# --- ALL FUNCTION DEFINITIONS ARE HERE ---

def run_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout
        else:
            return f"Error:\n{stderr}"
    except FileNotFoundError:
        return "Command not found."
    except Exception as e:
        return f"An error occurred: {e}"

def dns_lookup(domain):
    try:
        result = ""
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result += f"\n{record_type} Records:\n"
                for rdata in answers:
                    result += f"  {rdata}\n"
            except dns.resolver.NXDOMAIN:
                pass  # Handle cases where a record type doesn't exist
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                result += f"Error for {record_type} records: {e}\n"
        return result
    except Exception as e:
        return f"DNS Lookup Error: {e}"

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return str(w)  # Convert whois object to string
    except Exception as e:
        return f"Whois Lookup Error: {e}"

def geoip_lookup(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data['status'] == 'success':
            return str(data)  # Return GeoIP data as a string
        else:
            return f"GeoIP Error: {data['message']}"
    except Exception as e:
        return f"GeoIP Lookup Error: {e}"

def subnet_lookup(ip_address):
    try:
        ip_network = ipaddress.ip_network(ip_address, strict=False)  # strict False to allow host bits
        return str(ip_network)
    except ValueError:
        return "Invalid IP address or subnet."
    except Exception as e:
        return f"Error: {e}"

def port_scan(target, port_range):
    try:
        ports = [int(p) for p in port_range.split('-')] if '-' in port_range else [int(port_range)]
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set a timeout for the connection attempt
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        if open_ports:
            return f"Open ports: {', '.join(map(str, open_ports))}"
        else:
            return "No open ports found."
    except ValueError:
        return "Invalid port range."
    except socket.gaierror:
        return "Invalid target host."
    except Exception as e:
        return f"Port Scan Error: {e}"

def extract_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = [link.get('href') for link in soup.find_all('a')]
        return "\n".join(filter(None, links))  # filter to remove None values
    except requests.exceptions.RequestException as e:
        return f"Error extracting links: {e}"
    except Exception as e:
        return f"An error occurred: {e}"

def zone_transfer(domain):
    try:
        answers = dns.resolver.resolve(domain, 'AXFR')  # Note: AXFR requires special DNS server configuration
        result = ""
        for rdata in answers:
            result += f"{rdata}\n"
        return result
    except dns.resolver.NXDOMAIN:
        return "Domain not found."
    except dns.exception.DNSException as e:
        return f"Zone Transfer Error: {e}"

def http_header(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return str(headers)
    except requests.exceptions.RequestException as e:
        return f"HTTP Header Error: {e}"
    except Exception as e:
        return f"An error occurred: {e}"

def host_finder(ip_address):
    try:
        addr = socket.gethostbyaddr(ip_address)
        return str(addr)
    except socket.herror:
        return "Host not found for given IP."
    except Exception as e:
        return f"Error: {e}"

def ip_locator(ip_address):
    return geoip_lookup(ip_address)  # IP Locator uses GeoIP

def traceroute(target):
    command = f"traceroute {target}"
    return run_command(command)

def robots_txt(url):
    try:
        robots_url = url + "/robots.txt"
        response = requests.get(robots_url)
        if response.status_code == 200:
            return response.text
        else:
            return "robots.txt not found."
    except requests.exceptions.RequestException as e:
        return f"Robots.txt Error: {e}"
    except Exception as e:
        return f"An error occurred: {e}"

def host_dns_finder(hostname):
    try:
        result = ""
        try:
            ip = socket.gethostbyname(hostname)
            result += f"IP Address: {ip}\n"
        except socket.gaierror:
            result += "Could not resolve hostname.\n"

        try:
            records = dns.resolver.resolve(hostname)  # Resolve all record types
            result += "\nDNS Records:\n"
            for rdata in records:
                result += f"  {rdata}\n"
        except dns.resolver.NXDOMAIN:
            result += "Domain not found.\n"
        except Exception as e:
            result += f"Error fetching DNS records: {e}\n"
        return result
    except Exception as e:
        return f"Error: {e}"

def reverse_ip_lookup(ip_address):
    try:
        result = socket.getfqdn(ip_address)
        return result
    except socket.herror:
        return "No hostname found for that IP."
    except Exception as e:
        return f"Error: {e}"

def collect_emails(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        emails = set()  # Use a set to avoid duplicates
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if "mailto:" in href:
                email = href.replace("mailto:", "")
                emails.add(email)
        for element in soup.find_all(text=lambda text: text and "@" in text):
            email = element.strip()
            emails.add(email)

        return "\n".join(emails)
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
    except Exception as e:
        return f"An error occurred: {e}"

def subdomain_finder(domain):
    try:
        subdomains = []
        with open("subdomains.txt", "r") as f:  # You'll need a subdomains wordlist file
            for subdomain in f:
                subdomain = subdomain.strip()
                full_domain = f"{subdomain}.{domain}"
                try:
                    socket.gethostbyname(full_domain)  # Check if subdomain resolves
                    subdomains.append(full_domain)
                except socket.gaierror:
                    pass  # Subdomain doesn't exist
        return "\n".join(subdomains)
    except FileNotFoundError:
        return "subdomains.txt file not found. Create one with a list of subdomains."
    except Exception as e:
        return f"Error: {e}"

def install_update():
    # Add your install/update commands here.  Example:
    try:
        command = "apt update && apt upgrade -y"  # For Debian/Ubuntu systems
        # command = "yum update -y" # For RedHat/CentOS systems
        # command = "brew update" # For MacOS (if you have brew)
        result = run_command(command)
        return result
    except Exception as e:
        return f"Install/Update Error: {e}"

def run_tool(tool_function, *args):
    try:
        result = tool_function(*args)
        output_text.delete("1.0", tk.END)  # Clear previous output
        output_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

root = tk.Tk()
root.title("InfoWeb Tool")

# Styling (Optional, but makes the GUI look better)
style = ttk.Style()
style.theme_use("clam")  # or "alt", "default", "classic"

# Output Text Area (using ScrolledText for scrollbars)
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD)
output_text.pack(fill=tk.BOTH, expand=True)

# Frame for Buttons
button_frame = ttk.LabelFrame(root, text="Tools")  # Use a LabelFrame
button_frame.pack(fill=tk.X, padx=10, pady=10)

# Entry Fields (Added for input)
entry_domain = ttk.Entry(root)
entry_domain.pack(fill=tk.X, padx=10, pady=(0, 10))  # Pad only at the top
entry_domain.insert(0, "example.com")  # Example default value

entry_ip = ttk.Entry(root)
entry_ip.pack(fill=tk.X, padx=10, pady=(0, 10))
entry_ip.insert(0, "8.8.8.8")  # Example default value

entry_target = ttk.Entry(root)  # For port scan and traceroute
entry_target.pack(fill=tk.X, padx=10, pady=(0, 10))
entry_target.insert(0, "google.com")  # Example default value

entry_port_range = ttk.Entry(root)  # For port scan
entry_port_range.pack(fill=tk.X, padx=10, pady=(0, 10))
entry_port_range.insert(0, "80-443")  # Example default value

entry_url = ttk.Entry(root)
entry_url.pack(fill=tk.X, padx=10, pady=(0, 10))
entry_url.insert(0, "https://www.google.com")  # Example default value

# Buttons (Corrected command calls)
ttk.Button(button_frame, text="DNS Lookup", command=lambda: run_tool(dns_lookup, entry_domain.get())).grid(row=0, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="Whois Lookup", command=lambda: run_tool(whois_lookup, entry_domain.get())).grid(row=0, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="GeoIP Lookup", command=lambda: run_tool(geoip_lookup, entry_ip.get())).grid(row=1, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="Subnet Lookup", command=lambda: run_tool(subnet_lookup, entry_ip.get())).grid(row=1, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Port Scan", command=lambda: run_tool(port_scan, entry_target.get(), entry_port_range.get())).grid(row=2, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="Extract Links", command=lambda: run_tool(extract_links, entry_url.get())).grid(row=2, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Zone Transfer", command=lambda: run_tool(zone_transfer, entry_domain.get())).grid(row=3, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="HTTP Header", command=lambda: run_tool(http_header, entry_url.get())).grid(row=3, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Host Finder", command=lambda: run_tool(host_finder, entry_ip.get())).grid(row=4, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="IP Locator", command=lambda: run_tool(ip_locator, entry_ip.get())).grid(row=4, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Traceroute", command=lambda: run_tool(traceroute, entry_target.get())).grid(row=5, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="Robots.txt", command=lambda: run_tool(robots_txt, entry_url.get())).grid(row=5, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Host DNS Finder", command=lambda: run_tool(host_dns_finder, entry_domain.get())).grid(row=6, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="Reverse IP Lookup", command=lambda: run_tool(reverse_ip_lookup, entry_ip.get())).grid(row=6, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Collect Emails", command=lambda: run_tool(collect_emails, entry_url.get())).grid(row=7, column=0, padx=5, pady=5)
ttk.Button(button_frame, text="Subdomain Finder", command=lambda: run_tool(subdomain_finder, entry_domain.get())).grid(row=7, column=1, padx=5, pady=5)
ttk.Button(button_frame, text="Install/Update", command=lambda: run_tool(install_update)).grid(row=8, column=0, columnspan=2, padx=5, pady=5)



root.mainloop()
