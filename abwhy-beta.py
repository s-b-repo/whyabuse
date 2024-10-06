import requests
import os
import flask
from flask import request, jsonify
import daemon
from threading import Thread

# Flask app for API
app = flask.Flask(__name__)

# Top 5 Sources (replace these with real URLs to download lists)
sources = {
    "AbuseIPDB": "https://www.abuseipdb.com/download/json",
    "Spamhaus": "https://www.spamhaus.org/drop/drop.txt",
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "IPVoid": "https://www.ipvoid.com/files/banned_ips.txt",
    "FireHOL": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
}

banned_ips = set()
api_mode = False

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
        for name, url in sources.items():
            print(f"Downloading banned IPs from {name}...")
            download_ips(url)
        
        with open("banned_ips.txt", "w") as f:
            for ip in banned_ips:
                f.write(f"{ip}\n")
        print(f"Downloaded and saved {len(banned_ips)} banned IPs.")
    else:
        load_saved_ips()
else:
    for name, url in sources.items():
        print(f"Downloading banned IPs from {name}...")
        download_ips(url)
    
    with open("banned_ips.txt", "w") as f:
        for ip in banned_ips:
            f.write(f"{ip}\n")
    print(f"Downloaded and saved {len(banned_ips)} banned IPs.")

# API Key for Secure Access
server_api_key = input("Set a secure API key for access: ").strip()

# Prompt for external API keys
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
                return response.json()
            else:
                return {"error": f"AlienVault lookup failed, status code: {response.status_code}"}
        except Exception as e:
            return {"error": f"Error with AlienVault lookup: {e}"}
    return {"message": "AlienVault lookup skipped (no API key provided)."}

def virus_total_lookup(ip):
    if virus_total_key:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": virus_total_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"VirusTotal lookup failed, status code: {response.status_code}"}
        except Exception as e:
            return {"error": f"Error with VirusTotal lookup: {e}"}
    return {"message": "VirusTotal lookup skipped (no API key provided)."}

# Search for a specific IP
def search_ip(ip_address):
    is_banned = ip_address in banned_ips
    results = {"ip": ip_address, "banned": is_banned}
    if is_banned:
        print(f"{ip_address} is banned.")
    else:
        print(f"{ip_address} is not found in the banned list.")
    results["AlienVault"] = alien_vault_lookup(ip_address)
    results["VirusTotal"] = virus_total_lookup(ip_address)
    return results

# API route for searching IPs
@app.route('/api/search_ip', methods=['GET'])
def api_search_ip():
    if request.args.get('api_key') != server_api_key:
        return jsonify({"error": "Invalid API key"}), 403
    ip_address = request.args.get('ip')
    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400
    return jsonify(search_ip(ip_address))

# Run the API server
def run_server():
    print("Starting API server...")
    app.run(host='0.0.0.0', port=5000)

# Daemon mode
def run_as_daemon():
    with daemon.DaemonContext():
        run_server()

# Ask if API mode with daemon
api_mode_choice = input("Do you want to run in API mode as a daemon? (y/n): ").strip().lower()
if api_mode_choice == 'y':
    api_mode = True
    print("Running in API mode with daemon support...")
    daemon_thread = Thread(target=run_as_daemon)
    daemon_thread.start()
else:
    # Non-daemonized search mode
    ip_to_search = input("Enter the IP address you want to search: ").strip()
    print(search_ip(ip_to_search))
