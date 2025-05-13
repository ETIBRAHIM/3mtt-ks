import re

def check_phishing(url):
    # Expanded list of Nigerian scam patterns
    red_flags = {
        # URL shorteners (Bit.ly, TinyURL, etc.)
        "url_shorteners": r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|shorte\.st|adf\.ly|t\.co|buff\.ly)\/",
        
        # Fake bank domains (GTBank, Zenith, etc.)
        "bank_scams": r"(gtbank|zenith|access|uba|firstbank|fbn|unionbank)[^\.]*\.(com|ng|net|org)\b",
        
        # Urgent/emotional triggers
        "urgency_words": r"(claim|reward|bonus|urgent|verify|account|suspended|password|expire|winner|congratulations)",
        
        # Fake lottery/job offers
        "lottery_scams": r"(lott[o|e]ry|job|offer|apply|interview|employment|vacancy)[^\.]*\.(com|ng)",
        
        # Suspicious URL structures
        "fake_subdomains": r"(http(s)?:\/\/)?(www\.)?([a-z0-9]+\.)?(secure|update|login|verify)[^\.]*\.(com|ng)",
        
        # IP addresses
        "ip_address": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        
        # New: Common Nigerian scam keywords
        "nigerian_scams": r"(efcc|ndlea|nnpc|central bank|sim swap|atm card|wire transfer)",
    }

    # Check each red flag
    warnings = []
    for rule_name, pattern in red_flags.items():
        if re.search(pattern, url, re.IGNORECASE):
            if rule_name == "url_shorteners":
                warnings.append("⚠️ URL SHORTENER! bit.ly links often hide scams.")
            elif rule_name == "bank_scams":
                warnings.append("⚠️ FAKE BANK LINK! Mimics a Nigerian bank domain.")
            elif rule_name == "urgency_words":
                warnings.append("⚠️ SUSPICIOUS WORDS! 'Urgent' = scam tactic.")
            elif rule_name == "lottery_scams":
                warnings.append("⚠️ FAKE LOTTERY/JOB! Classic Nigerian scam.")
            elif rule_name == "fake_subdomains":
                warnings.append("⚠️ FAKE SUBDOMAIN! Scammers use 'secure-update.com'.")
            elif rule_name == "ip_address":
                warnings.append("⚠️ IP ADDRESS! Legit sites don't use raw IPs.")
            elif rule_name == "nigerian_scams":
                warnings.append("⚠️ NIGERIAN SCAM ALERT! Mentions 'EFCC' or 'wire transfer'.")

    return warnings

def main():
    print("=== NIGERIAN PHISHING LINK DETECTOR ===")
    print("Type 'quit' to exit\n")
    
    while True:
        url = input("Paste a URL to check: ").strip()
        
        if url.lower() == 'quit':
            print("Goodbye! Stay safe from scams!")
            break
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url  # Auto-add protocol if missing
            
        warnings = check_phishing(url)
        
        if warnings:
            print("\n".join(warnings))
            print("🚨 DON'T CLICK! THIS LINK IS UNSAFE.\n")
        else:
            print("✅ Link looks safe (but always verify the URL!)\n")

if __name__ == "__main__":
    main()