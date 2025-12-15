import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import json
import os
from colorama import init, Fore

init(autoreset=True)

class IntelligentCrawler:
    def __init__(self, base_url="http://localhost:8088"):
        self.base_url = base_url
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.inputs = []
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "WebScanPro/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
    
    def login_to_dvwa(self):
        """Login to DVWA"""
        try:
            print(f"{Fore.YELLOW}[*] Attempting to login to DVWA...")
            
            # First get the login page to get CSRF token
            response = self.session.get(self.base_url + "/login.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find CSRF token
            csrf_token = ""
            csrf_input = soup.find('input', {'name': 'user_token'})
            if csrf_input:
                csrf_token = csrf_input.get('value', '')
            
            # Prepare login data
            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": csrf_token
            }
            
            # Submit login
            response = self.session.post(self.base_url + "/login.php", data=login_data)
            
            if "Login failed" not in response.text:
                print(f"{Fore.GREEN}[+] Successfully logged in to DVWA!")
                
                # Set security level to LOW
                security_data = {
                    "security": "low",
                    "seclev_submit": "Submit"
                }
                self.session.post(self.base_url + "/security.php", data=security_data)
                print(f"{Fore.GREEN}[+] Security level set to LOW")
                return True
            else:
                print(f"{Fore.RED}[-] Login failed! Check credentials")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Login error: {e}")
            return False
    
    def crawl(self, start_url=None):
        """Crawl the application"""
        if start_url is None:
            start_url = self.base_url
        
        print(f"{Fore.CYAN}[*] Starting crawl from: {start_url}")
        
        to_visit = [start_url]
        max_pages = 15
        
        while to_visit and len(self.visited_urls) < max_pages:
            url = to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
            
            try:
                print(f"{Fore.WHITE}[*] Crawling: {url}")
                response = self.session.get(url, timeout=10)
                self.visited_urls.add(url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms from this page
                    self._extract_forms(url, soup)
                    
                    # Extract and add new links
                    new_links = self._extract_links(url, soup)
                    for link in new_links:
                        if link not in self.visited_urls and link not in to_visit:
                            to_visit.append(link)
                    
                    time.sleep(0.3)  # Be polite
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error crawling {url}: {e}")
        
        print(f"{Fore.GREEN}[+] Crawl complete! Visited {len(self.visited_urls)} pages")
        return True
    
    def _extract_forms(self, url, soup):
        """Extract forms from page"""
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'page_url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Get all input elements
            for tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'tag': tag.name,
                    'type': tag.get('type', 'text'),
                    'name': tag.get('name', ''),
                    'id': tag.get('id', ''),
                    'value': tag.get('value', ''),
                    'placeholder': tag.get('placeholder', '')
                }
                
                form_data['inputs'].append(input_info)
                
                # Add to global inputs list
                self.inputs.append({
                    'page': url,
                    'form_action': form.get('action', ''),
                    **input_info
                })
            
            if form_data['inputs']:
                self.forms.append(form_data)
                print(f"{Fore.GREEN}[+] Found form with {len(form_data['inputs'])} inputs on {url}")
    
    def _extract_links(self, url, soup):
        """Extract links from page"""
        links = []
        base_domain = urlparse(self.base_url).netloc
        
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            
            # Skip unwanted links
            if not href or href.startswith(('javascript:', '#', 'mailto:')):
                continue
            
            # Make absolute URL
            absolute_url = urljoin(url, href)
            parsed_url = urlparse(absolute_url)
            
            # Only follow same-domain links
            if parsed_url.netloc == base_domain or not parsed_url.netloc:
                # Clean up the URL
                clean_url = absolute_url.split('#')[0]  # Remove fragments
                if clean_url not in self.visited_urls and clean_url not in links:
                    links.append(clean_url)
        
        return links
    
    def get_dvwa_vulnerability_pages(self):
        """Get DVWA vulnerability pages"""
        vuln_pages = [
            "/vulnerabilities/sqli/",
            "/vulnerabilities/sqli_blind/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
            "/vulnerabilities/csrf/",
            "/vulnerabilities/brute/",
            "/vulnerabilities/exec/",
            "/vulnerabilities/fi/",
            "/vulnerabilities/upload/",
            "/vulnerabilities/captcha/",
            "/vulnerabilities/weak_id/"
        ]
        
        urls = [self.base_url + page for page in vuln_pages]
        
        # Visit each vulnerability page
        for url in urls:
            if url not in self.visited_urls:
                try:
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        self.visited_urls.add(url)
                        soup = BeautifulSoup(response.text, 'html.parser')
                        self._extract_forms(url, soup)
                        print(f"{Fore.GREEN}[+] Added DVWA vulnerability page: {url}")
                    time.sleep(0.2)
                except:
                    pass
        
        return True
    
    def save_results(self):
        """Save all crawl results"""
        os.makedirs("output", exist_ok=True)
        
        results = {
            'target': self.base_url,
            'total_pages': len(self.visited_urls),
            'total_forms': len(self.forms),
            'total_inputs': len(self.inputs),
            'pages': list(self.visited_urls),
            'forms': self.forms,
            'inputs': self.inputs,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save JSON
        with open('output/crawl_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        # Save URLs list
        with open('output/urls.txt', 'w', encoding='utf-8') as f:
            for url in self.visited_urls:
                f.write(url + '\n')
        
        print(f"{Fore.GREEN}[+] Results saved to output/crawl_results.json")
        return results