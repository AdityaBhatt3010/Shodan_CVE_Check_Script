import shodan
import requests

# ===== Configuration =====
# Shodan API Key
SHODAN_API_KEY = "your_shodan_api_key_here"

# CVE threshold (CVSS score) for critical vulnerabilities
CVSS_THRESHOLD = 7.0

# ===========================

def query_cve(product):
    # Query the CIRCL CVE API for vulnerabilities related to the product.
    url = f"https://cve.circl.lu/api/search/{product}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()  # Expected to return JSON data with a 'results' field.
        else:
            print(f"Error querying CVE for {product}: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"Exception querying CVE for {product}: {e}")
        return None

def check_critical_vulnerabilities(cve_data, threshold=CVSS_THRESHOLD):
    # Filter the CVE data for vulnerabilities with a CVSS score at or above the threshold.
    critical_cves = []
    if not cve_data or 'results' not in cve_data:
        return critical_cves
    for cve in cve_data['results']:
        cvss_score = cve.get('cvss', 0)
        if cvss_score and cvss_score >= threshold:
            critical_cves.append({
                'id': cve.get('id', 'N/A'),
                'cvss': cvss_score,
                'summary': cve.get('summary', 'No summary available.')
            })
    return critical_cves

def scan_target(target_ip):
    # Scan the target IP using Shodan, extract product information and check for critical vulnerabilities via CVE data.
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(target_ip)
        print(f"Scanning IP: {host['ip_str']}")
        for service in host.get('data', []):
            product = service.get('product')
            if product:
                port = service.get('port')
                print(f"\nChecking product: {product} on port {port}")
                cve_data = query_cve(product)
                critical_cves = check_critical_vulnerabilities(cve_data)
                if critical_cves:
                    print(f"Critical vulnerabilities found for {product} (port {port}):")
                    for cv in critical_cves:
                        print(f" - {cv['id']} (CVSS: {cv['cvss']}): {cv['summary']}")
                else:
                    print(f"No critical vulnerabilities found for {product} on port {port}.")
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")

if __name__ == "__main__":
    target_ip = input("Enter target IP: ").strip()
    if target_ip:
        scan_target(target_ip)
    else:
        print("No target IP provided.")
