from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from datetime import datetime, timedelta
import os

app = FastAPI()

CA_KEY_PATH = "ca/summoner_ca.key"
CA_CERT_PATH = "ca/summoner_ca.crt"
OUTPUT_DIR = "issued_certs"

class CertRequest(BaseModel):
    common_name: str
    public_key_pem: str  # PEM-formatted public key from agent
    dns_names: list[str] = []
    kyc_level: int = 1  # Customizable policy level

@app.post("/delegate_certificate")
def delegate_certificate(req: CertRequest):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # Load CA key
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), None)

        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Load agent's provided public key
        agent_pubkey = load_pem_public_key(req.public_key_pem.encode())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, req.common_name)
        ])

        san = x509.SubjectAlternativeName([
            x509.DNSName(name) for name in req.dns_names
        ])

        now = datetime.utcnow()
        cert_builder = x509.CertificateBuilder(
        ).subject_name(subject
        ).issuer_name(ca_cert.subject
        ).public_key(agent_pubkey
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(now
        ).not_valid_after(now + timedelta(days=7)
        ).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        ).add_extension(san, critical=False
        ).add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier(f"1.3.6.1.4.1.60183.1.{req.kyc_level}"),
                policy_qualifiers=[
                    x509.UserNotice(notice_reference=None, explicit_text=f"KYC Level {req.kyc_level}")
                ]
            )
        ]), critical=False)


        # Sign certificate with CA key
        cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

        # Save certificate
        filename = f"{req.common_name}_{int(now.timestamp())}.crt"
        cert_path = os.path.join(OUTPUT_DIR, filename)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return {
            "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
