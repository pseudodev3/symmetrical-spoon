import requests
import urllib3

# Disable insecure request warnings if you are testing locally with self-signed SSL certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_sensitive_files(base_url):
    print("\n[*] Checking for exposed sensitive files and directories...")
    # Common paths that attackers look for on e-commerce and web servers
    sensitive_paths = [
        '/.git/', '/.env', '/config.php', '/wp-config.php.bak', 
        '/admin', '/administrator', '/backup.zip', '/phpinfo.php', '/server-status'
    ]
    
    for path in sensitive_paths:
        target = f"{base_url}{path}"
        try:
            # We use a HEAD request to quickly check existence without downloading the whole file
            response = requests.head(target, verify=False, timeout=3)
            
            if response.status_code == 200:
                print(f"[!] CRITICAL: Found exposed endpoint: {target} (Status: 200)")
            elif response.status_code in [401, 403]:
                print(f"[+] Found restricted endpoint: {target} (Status: {response.status_code}) - Good, access is denied.")
        except requests.exceptions.RequestException:
            pass

def check_http_methods(base_url):
    print("\n[*] Checking allowed HTTP methods...")
    try:
        # An OPTIONS request asks the server what communication methods it supports
        response = requests.options(base_url, verify=False, timeout=3)
        if 'Allow' in response.headers:
            methods = response.headers['Allow']
            print(f"[+] Allowed Methods: {methods}")
            if 'PUT' in methods or 'DELETE' in methods:
                print("[!] WARNING: 'PUT' or 'DELETE' methods are enabled. Ensure this is restricted to admins only.")
        else:
            print("[-] Server did not return 'Allow' headers.")
    except requests.exceptions.RequestException:
        pass

def check_cookie_security(base_url):
    print("\n[*] Checking session cookie security flags...")
    try:
        response = requests.get(base_url, verify=False, timeout=3)
        cookies = response.cookies
        
        if not cookies:
            print("[-] No cookies set by the server on the initial request.")
            return

        for cookie in cookies:
            print(f"\n[+] Analyzing Cookie: {cookie.name}")
            if not cookie.secure:
                print(f"    [!] Missing 'Secure' flag: This cookie can be intercepted over unencrypted HTTP.")
            else:
                print(f"    [+] 'Secure' flag is present.")
                
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print(f"    [!] Missing 'HttpOnly' flag: This cookie is vulnerable to theft via Cross-Site Scripting (XSS).")
            else:
                print(f"    [+] 'HttpOnly' flag is present.")
                
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking cookies: {e}")

if __name__ == "__main__":
    print("=== Local E-commerce Vulnerability Scanner ===")
    url = input("Enter the full URL of your local site (e.g., http://localhost:8080 or http://192.168.1.10): ").strip()
    
    if not url.startswith("http"):
        print("[!] Please include http:// or https:// in your URL.")
    else:
        # Remove trailing slash if the user added one
        if url.endswith("/"):
            url = url[:-1]
            
        check_sensitive_files(url)
        check_http_methods(url)
        check_cookie_security(url)
        print("\n[*] Scan complete.")
