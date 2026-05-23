import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Threat Intelligence Phishing Analyzer API")

# Enable CORS so our React frontend can talk to it safely
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- THREAT INTELLIGENCE DATABASES ---
# High-risk keywords commonly used in social engineering to induce panic/urgency
SUSPICIOUS_KEYWORDS = [
    "urgent", "action required", "suspended", "compromised", "verify your account",
    "security alert", "login immediately", "wire transfer", "unauthorized login",
    "password expired", "irs notice", "crypto", "free gift"
]

# Simulated global domain blocklist (Threat Intel Feed)
MALICIOUS_DOMAINS = {
    "secure-bank-login.net",
    "update-paypal-security.com",
    "netflix-billing-verify.co",
    "crypto-airdrop-rewards.xyz",
    "login-microsoft365-auth.icu",
    "verify-amazon-funds.info"
}

# --- DATA MODELS ---
class EmailPayload(BaseModel):
    content: str

# --- THE FORENSIC CORE ---
def extract_domains(text):
    """Uses Regex to extract domains from any URLs found in the text."""
    # Matches http://, https://, or plain www. domains
    url_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)'
    urls = re.findall(url_pattern, text)
    return list(set(urls)) # Remove duplicates

def analyze_text(text):
    """Analyzes text for indicators of social engineering and malicious infrastructure."""
    text_lower = text.lower()
    detected_keywords = []
    detected_malicious_domains = []
    
    # 1. Check for Urgency/Social Engineering Keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            
    # 2. Extract and Verify Infrastructure/URLs
    extracted_domains = extract_domains(text)
    for domain in extracted_domains:
        if domain.lower() in MALICIOUS_DOMAINS:
            detected_malicious_domains.append(domain)

    # 3. Calculate Threat Risk Score (0 to 100)
    score = 0
    score += len(detected_keywords) * 15
    if len(extracted_domains) > 0:
        score += 20 # General penalty for including links in unverified emails
    if len(detected_malicious_domains) > 0:
        score += 50 # Massive critical penalty for matching known threat feeds
        
    # Cap the threat score at 100
    threat_score = min(score, 100)

    # Determine Threat Assessment Tier
    if threat_score >= 70:
        verdict = "MALICIOUS (High Risk)"
    elif threat_score >= 30:
        verdict = "SUSPICIOUS (Medium Risk)"
    else:
        verdict = "CLEAN (Low Risk)"

    return {
        "threat_score": threat_score,
        "verdict": verdict,
        "domains_found": extracted_domains,
        "malicious_domains_matched": detected_malicious_domains,
        "social_engineering_indicators": detected_keywords
    }

# --- API ENDPOINTS ---
@app.post("/api/analyze")
def analyze_email_endpoint(payload: EmailPayload):
    """Ingests raw email strings and returns a structural threat report."""
    report = analyze_text(payload.content)
    return report

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)