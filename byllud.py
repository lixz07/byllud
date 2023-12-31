import os
import requests
from bs4 import BeautifulSoup
import re
import socket
from tabulate import tabulate
from colorama import init, Fore, Style
from langdetect import detect

init(autoreset=True)

CLEAR_COMMAND = 'cls' if os.name == 'nt' else 'clear'

def clear_screen():
    os.system(CLEAR_COMMAND)

def display_drawing(drawing):
    print(f"{Fore.YELLOW}{drawing}")

def validate_url(url):
    if not re.match(r'https?://', url):
        return 'http://' + url
    return url

def resolve_ip(target_url):
    try:
        ip_address = socket.gethostbyname(target_url)
        return ip_address
    except socket.gaierror:
        return None

def fetch_server_response(target_url):
    try:
        response = requests.get(target_url)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error fetching server response: {e}")

def analyze_site(response):
    results = {
        "Forms": 0,
        "User Input Fields": 0,
        "External Links": 0,
        "Hidden Links": 0,
        "Cookies": None,
        "Content Security Policy Header": None,
        "HTTP Strict Transport Security Header": None,
        "Admin Login Page Found": False,
        "XSS Detected": False,
        "Website Language": None,
    }

    if response.status_code == 200:
        results["Request Status"] = "Successful"
    else:
        results["Request Status"] = "Error"

    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")
    results["Forms"] = len(forms)

    input_fields = soup.find_all("input", {"type": ["text", "password", "email"]})
    results["User Input Fields"] = len(input_fields)

    # XSS Detection: Check for potential script injection in input fields
    for input_field in input_fields:
        if input_field.get("name") and any(re.search(pattern, str(input_field), re.IGNORECASE) for pattern in ['<script', 'alert\(', 'onerror']):
            results["XSS Detected"] = True
            break

    external_links = [a["href"] for a in soup.find_all("a", href=re.compile(r"^(http|www)"))]
    results["External Links"] = len(external_links)

    all_links = [a["href"] for a in soup.find_all("a", href=True)]
    visible_links = set(external_links)
    hidden_links = [link for link in all_links if link not in visible_links]
    results["Hidden Links"] = len(hidden_links)

    cookies = response.cookies
    if cookies:
        results["Cookies"] = str(cookies)

    csp_header = response.headers.get("Content-Security-Policy")
    hsts_header = response.headers.get("Strict-Transport-Security")

    if csp_header:
        results["Content Security Policy Header"] = csp_header

    if hsts_header:
        results["HTTP Strict Transport Security Header"] = hsts_header

    admin_keywords = ["admin", "login", "panel", "administrator"]
    for keyword in admin_keywords:
        if any(keyword in link.lower() for link in all_links):
            results["Admin Login Page Found"] = True
            break

    return results

def detect_website_language(response):
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        text = BeautifulSoup(response.text, "html.parser").get_text()
        language = detect(text)
        return language
    else:
        return "Unknown"

def display_results(results):
    print(f"\n{Fore.RED}Results:")
    table = []
    for key, value in results.items():
        table.append([key, value])
    print(tabulate(table, headers=["Category", "Value"], tablefmt="grid"))

def main():
    clear_screen()
    display_drawing(ascii_art)

    target_url = input("Target URL: ")
    target_url = validate_url(target_url)

    ip_address = resolve_ip(target_url)
    if ip_address:
        print(f"\n[IP Address] The IP address of {target_url} is {ip_address}")
    else:
        print(f"\n[IP Address] Unable to resolve the IP address for {target_url}")

    try:
        response = fetch_server_response(target_url)
        print(f"\n[Servers Response] Servers respond smoothly.")

        website_language = detect_website_language(response)
        print(f"\n[Website Language] Estimated language: {website_language}")

        results = analyze_site(response)
        results["Website Language"] = website_language
        display_results(results)

        if results["Admin Login Page Found"]:
            print("\n[Admin Login Page] Possible admin login page found.")
        else:
            print("\n[Admin Login Page] No admin login page found.")

        if results["XSS Detected"]:
            print(f"\n{Fore.RED}[XSS Detected] Potential Cross-Site Scripting (XSS) vulnerability found.")
        else:
            print(f"\n{Fore.GREEN}[XSS Detected] No Cross-Site Scripting (XSS) vulnerability detected.")

    except Exception as e:
        print(f"\n{Fore.RED}[Error] {str(e)}")

if __name__ == "__main__":
    ascii_art = f"""
    {Fore.YELLOW}
 ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄     ▄▄▄     ▄▄   ▄▄ ▄▄▄▄▄▄  
█  ▄    █  █ █  █   █   █   █   █  █ █  █      █ 
█ █▄█   █  █▄█  █   █   █   █   █  █ █  █  ▄    █
█       █       █   █   █   █   █  █▄█  █ █ █   █
█  ▄   ██▄     ▄█   █▄▄▄█   █▄▄▄█       █ █▄█   █
█ █▄█   █ █   █ █       █       █       █       █
█▄▄▄▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄█ 
    """
    main()
