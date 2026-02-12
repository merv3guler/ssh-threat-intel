import os
import re
import json
import requests
from datetime import datetime

# Configuration
LOG_DIR = 'logs'
EXPORT_FILE = 'public/data.json'
ABUSE_API_URL = 'https://api.abuseipdb.com/api/v2/check'
ABUSE_API_KEY = os.environ.get('ABUSEIPDB_KEY')
API_LIMIT = 15  # <--- GÜNCELLEME: Limiti buradan yönetebilirsin (Max 15)

def parse_auth_logs():
    """Scans log directory and extracts failed login attempts."""
    ip_counts = {}
    pattern = re.compile(r'Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    if not os.path.exists(LOG_DIR):
        print(f"Warning: {LOG_DIR} directory not found.")
        return {}

    for log_file in os.listdir(LOG_DIR):
        file_path = os.path.join(LOG_DIR, log_file)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    matches = pattern.findall(content)
                    for ip in matches:
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
            except Exception as e:
                print(f"Error reading {log_file}: {e}")
    
    return ip_counts

def get_ip_reputation(ip):
    """Fetches reputation score from AbuseIPDB."""
    if not ABUSE_API_KEY:
        return None
    
    headers = {
        'Key': ABUSE_API_KEY,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    
    try:
        response = requests.get(ABUSE_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['data']
        elif response.status_code == 429:
            print(f"API Rate Limit Exceeded for {ip}")
            return None
    except Exception as e:
        print(f"API request failed for {ip}: {e}")
    
    return None

def main():
    print("Starting Sentinel analysis...")
    
    # 1. Parse Logs
    attackers = parse_auth_logs()
    
    # 2. Sort and filter top attackers using configuration limit
    top_attackers = sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:API_LIMIT]
    
    enriched_data = []
    
    # 3. Enrich with Threat Intel
    for ip, count in top_attackers:
        print(f"Analyzing {ip} ({count} attempts)...")
        rep = get_ip_reputation(ip)
        
        # If API fails or limit hit, use default secure fallback
        entry = {
            "ip": ip,
            "count": count,
            "updated": datetime.utcnow().isoformat(),
            "score": rep.get('abuseConfidenceScore', 0) if rep else 0,
            "country": rep.get('countryCode', 'UNK') if rep else 'UNK',
            "isp": rep.get('isp', 'Unknown') if rep else 'Unknown'
        }
        enriched_data.append(entry)

    # 4. Export Data
    os.makedirs(os.path.dirname(EXPORT_FILE), exist_ok=True)
    with open(EXPORT_FILE, 'w') as f:
        json.dump(enriched_data, f, indent=2)
    
    print(f"Analysis complete. {len(enriched_data)} IPs exported.")

if __name__ == "__main__":
    main()
