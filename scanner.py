import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from colorama import Fore, Style, init

init(autoreset=True)

headers = {
    "User-Agent": "Mozilla/5.0 (VulnScanner)"
}

# SQLi payloads
sql_payloads = ["' OR 1=1--", "\" OR 1=1--", "' OR 'a'='a"]

# XSS payloads
xss_payloads = ["<script>alert('XSS')</script>", "\"><svg/onload=alert(1)>"]

def test_sql_injection(url):
    print(Fore.YELLOW + "[*] Testing SQL Injection...")
    for payload in sql_payloads:
        test_url = url + "?id=" + payload
        res = requests.get(test_url, headers=headers)
        if any(error in res.text.lower() for error in ["sql", "syntax", "mysql", "error in your"]):
            print(Fore.RED + f"[!] Possible SQL Injection at {test_url}")
            return
    print(Fore.GREEN + "[+] No SQL Injection detected.")

def test_xss(url):
    print(Fore.YELLOW + "[*] Testing XSS...")
    for payload in xss_payloads:
        test_url = url + "?q=" + payload
        res = requests.get(test_url, headers=headers)
        if payload in res.text:
            print(Fore.RED + f"[!] Possible XSS at {test_url}")
            return
    print(Fore.GREEN + "[+] No XSS detected.")

def test_clickjacking(url):
    print(Fore.YELLOW + "[*] Testing Clickjacking...")
    res = requests.get(url, headers=headers)
    if 'x-frame-options' not in res.headers:
        print(Fore.RED + "[!] Possible Clickjacking vulnerability (no X-Frame-Options header)")
    else:
        print(Fore.GREEN + "[+] X-Frame-Options header present.")

def test_csrf(url):
    print(Fore.YELLOW + "[*] Checking for CSRF protection...")
    res = requests.get(url, headers=headers)
    soup = BeautifulSoup(res.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all("input")
        has_token = any("token" in inp.get("name", "").lower() for inp in inputs)
        if not has_token:
            print(Fore.RED + "[!] Form may be vulnerable to CSRF (no CSRF token found)")
            return
    print(Fore.GREEN + "[+] CSRF token present in forms.")

def test_otp_bypass(url):
    print(Fore.YELLOW + "[*] Looking for OTP bypass clues...")
    res = requests.get(url, headers=headers)
    if re.search(r'otp\s*=\s*["\']?\d{4,6}["\']?', res.text.lower()):
        print(Fore.RED + "[!] Possible hardcoded OTP or weak validation found")
    else:
        print(Fore.GREEN + "[+] No OTP bypass patterns found.")

def test_api_security(url):
    print(Fore.YELLOW + "[*] Testing API for auth/misconfig...")
    res = requests.get(url, headers=headers)
    if res.status_code == 200 and "unauthorized" not in res.text.lower():
        print(Fore.RED + f"[!] API at {url} may be publicly accessible")
    else:
        print(Fore.GREEN + "[+] API seems protected.")

def run_all_tests(target_url):
    print(Fore.CYAN + f"\n[*] Scanning: {target_url}\n")
    test_sql_injection(target_url)
    test_xss(target_url)
    test_clickjacking(target_url)
    test_csrf(target_url)
    test_otp_bypass(target_url)
    test_api_security(target_url)

# Sample usage:
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ")
    run_all_tests(target)
