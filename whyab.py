import requests
import os

# Top 5 Sources (replace these with real URLs to download lists)
sources = {
    "AbuseIPDB": "https://www.abuseipdb.com/download/json",
    "Spamhaus": "https://www.spamhaus.org/drop/drop.txt",
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "IPVoid": "https://www.ipvoid.com/files/banned_ips.txt",
    "FireHOL": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
}

banned_ips = set()

# Function to download and process IPs
def download_ips(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            ips = response.text.splitlines()
            for ip in ips:
                banned_ips.add(ip.strip())
        else:
            print(f"Failed to download from {url}, status code: {response.status_code}")
    except Exception as e:
        print(f"Error downloading from {url}: {e}")

# Function to load IPs from a saved file
def load_saved_ips(filename="banned_ips.txt"):
    with open(filename, "r") as f:
        for line in f:
            banned_ips.add(line.strip())
    print(f"Loaded {len(banned_ips)} banned IPs from {filename}.")

# Check if IP list file exists
if os.path.exists("banned_ips.txt"):
    user_choice = input("IP list file found. Do you want to re-download the lists? (y/n): ").strip().lower()
    if user_choice == 'y':
        # Download IP lists from sources
        for name, url in sources.items():
            print(f"Downloading banned IPs from {name}...")
            download_ips(url)
        
        # Save IPs to file
        with open("banned_ips.txt", "w") as f:
            for ip in banned_ips:
                f.write(f"{ip}\n")
        print(f"Downloaded and saved {len(banned_ips)} banned IPs.")
    else:
        load_saved_ips()
else:
    # If file doesn't exist, download IPs
    for name, url in sources.items():
        print(f"Downloading banned IPs from {name}...")
        download_ips(url)
    
    # Save IPs to file
    with open("banned_ips.txt", "w") as f:
        for ip in banned_ips:
            f.write(f"{ip}\n")
    print(f"Downloaded and saved {len(banned_ips)} banned IPs.")

# Prompt for API keys if available
alien_vault_key = input("Enter your AlienVault API key (or leave blank to skip): ").strip()
virus_total_key = input("Enter your VirusTotal API key (or leave blank to skip): ").strip()

# AlienVault and VirusTotal Lookup Functions
def alien_vault_lookup(ip):
    if alien_vault_key:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": alien_vault_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                print(f"AlienVault report for {ip}:")
                print(data)
            else:
                print(f"AlienVault lookup failed for {ip}, status code: {response.status_code}")
        except Exception as e:
            print(f"Error with AlienVault lookup for {ip}: {e}")
    else:
        print("Skipping AlienVault lookup (no API key provided).")

def virus_total_lookup(ip):
    if virus_total_key:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": virus_total_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                print(f"VirusTotal report for {ip}:")
                print(data)
            else:
                print(f"VirusTotal lookup failed for {ip}, status code: {response.status_code}")
        except Exception as e:
            print(f"Error with VirusTotal lookup for {ip}: {e}")
    else:
        print("Skipping VirusTotal lookup (no API key provided).")

# Search for a specific IP
def search_ip(ip_address):
    if ip_address in banned_ips:
        print(f"{ip_address} is banned.")
    else:
        print(f"{ip_address} is not found in the banned list.")

    # Perform lookups if API keys are provided
    alien_vault_lookup(ip_address)
    virus_total_lookup(ip_address)

# Get user input for IP to search
ip_to_search = input("Enter the IP address you want to search: ").strip()
search_ip(ip_to_search)
