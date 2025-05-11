import requests
import subprocess
import os
import json

CERT_SERVICE_URL = "http://127.0.0.1:8000/delegate_certificate"
AGENT_COMMON_NAME = "agent-001.google.com"
DNS_NAMES = ["agent-001.google.com"]
KYC_LEVEL = 2  # adjust as necessary

# Generate RSA key-pair if not exists
def generate_key():
    if not os.path.exists("agent.key"):
        subprocess.run(["openssl", "genrsa", "-out", "agent.key", "2048"], check=True)
        print("✅ Generated agent.key")
    else:
        print("✅ agent.key already exists")

# Extract public key PEM from private key
def get_public_key_pem():
    result = subprocess.run(
        ["openssl", "rsa", "-in", "agent.key", "-pubout"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()

# Request certificate from service
def request_certificate(pub_key_pem):
    payload = {
        "common_name": AGENT_COMMON_NAME,
        "public_key_pem": pub_key_pem,
        "dns_names": DNS_NAMES,
        "kyc_level": KYC_LEVEL
    }

    resp = requests.post(CERT_SERVICE_URL, json=payload)
    if resp.status_code == 200:
        cert_pem = resp.json()["certificate_pem"]
        with open("agent.crt", "w") as f:
            f.write(cert_pem)
        print("✅ Received and saved agent.crt")
    else:
        print(f"❌ Failed to get certificate: {resp.status_code}, {resp.text}")

# Run process
if __name__ == "__main__":
    generate_key()
    public_key_pem = get_public_key_pem()
    request_certificate(public_key_pem)
