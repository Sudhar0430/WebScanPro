import json
import os
from datetime import datetime
from colorama import init, Fore

init(autoreset=True)

class WebScanner:
    def __init__(self, crawl_data):
        self.data = crawl_data
        self.analysis = {}
    
    def analyze(self):
        """Analyze the crawl data"""
        print(f"{Fore.YELLOW}[*] Analyzing crawl data...")
        
        # Basic statistics
        total_forms = len(self.data['forms'])
        total_inputs = len(self.data['inputs'])
        
        # Categorize inputs by type
        input_types = {}
        for inp in self.data['inputs']:
            input_type = inp.get('type', 'text')
            input_types[input_type] = input_types.get(input_type, 0) + 1
        
        # Find potential injection points
        injection_points = []
        for inp in self.data['inputs']:
            if inp['type'] in ['text', 'password', 'search', 'email', 'url']:
                injection_points.append({
                    'page': inp['page'],
                    'field_name': inp['name'],
                    'field_type': inp['type'],
                    'form_action': inp.get('form_action', '')
                })
        
        self.analysis = {
            'summary': {
                'target_url': self.data['target'],
                'pages_crawled': self.data['total_pages'],
                'forms_found': total_forms,
                'inputs_found': total_inputs,
                'injection_points': len(injection_points),
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            'input_types': input_types,
            'injection_points': injection_points,
            'pages': self.data['pages'],
            'forms': self.data['forms']
        }
        
        self._save_analysis()
        self._generate_html_report()
        
        return self.analysis
    
    def _save_analysis(self):
        """Save analysis to JSON"""
        with open('output/target_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(self.analysis, f, indent=2)
        print(f"{Fore.GREEN}[+] Analysis saved to output/target_analysis.json")
    
    def _generate_html_report(self):
        """Generate HTML report"""
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro - Target Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #667eea; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .vulnerable {{ color: #e74c3c; font-weight: bold; }}
        .safe {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WebScanPro Security Scan Report</h1>
            <p>Target Analysis | Generated: {self.analysis['summary']['scan_date']}</p>
        </div>
        
        <div class="card">
            <h2>📊 Scan Summary</h2>
            <div class="stat-grid">
                <div class="stat-box">
                    <div class="stat-number">{self.analysis['summary']['pages_crawled']}</div>
                    <div class="stat-label">Pages Crawled</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{self.analysis['summary']['forms_found']}</div>
                    <div class="stat-label">Forms Found</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{self.analysis['summary']['inputs_found']}</div>
                    <div class="stat-label">Input Fields</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{self.analysis['summary']['injection_points']}</div>
                    <div class="stat-label">Injection Points</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🎯 Target Information</h2>
            <p><strong>Target URL:</strong> {self.analysis['summary']['target_url']}</p>
            <p><strong>Scan Date:</strong> {self.analysis['summary']['scan_date']}</p>
        </div>
        
        <div class="card">
            <h2>🔍 Input Field Analysis</h2>
            <table>
                <tr>
                    <th>Input Type</th>
                    <th>Count</th>
                    <th>Risk Level</th>
                </tr>'''
        
        # Add input types
        for input_type, count in self.analysis['input_types'].items():
            risk = "Low"
            if input_type in ['text', 'password', 'search']:
                risk = "High"
            elif input_type in ['email', 'url']:
                risk = "Medium"
            
            risk_class = "safe" if risk == "Low" else "warning" if risk == "Medium" else "vulnerable"
            
            html += f'''
                <tr>
                    <td>{input_type}</td>
                    <td>{count}</td>
                    <td class="{risk_class}">{risk}</td>
                </tr>'''
        
        html += '''
            </table>
        </div>
        
        <div class="card">
            <h2>⚠️ Potential Injection Points</h2>
            <table>
                <tr>
                    <th>Page URL</th>
                    <th>Field Name</th>
                    <th>Field Type</th>
                    <th>Risk</th>
                </tr>'''
        
        # Add injection points
        for point in self.analysis['injection_points']:
            risk = "High" if point['field_type'] in ['text', 'password'] else "Medium"
            risk_class = "vulnerable" if risk == "High" else "warning"
            
            html += f'''
                <tr>
                    <td>{point['page'][:50]}...</td>
                    <td>{point['field_name'] or 'Unnamed'}</td>
                    <td>{point['field_type']}</td>
                    <td class="{risk_class}">{risk}</td>
                </tr>'''
        
        html += '''
            </table>
        </div>
        
        <div class="card">
            <h2>📄 Discovered Pages</h2>
            <ul>'''
        
        # Add pages
        for page in self.analysis['pages']:
            html += f'<li><a href="{page}" target="_blank">{page}</a></li>'
        
        html += '''
            </ul>
        </div>
        
        <div class="card">
            <h2>🔧 Recommendations</h2>
            <ol>
                <li>Test all text input fields for SQL Injection vulnerabilities</li>
                <li>Test all forms for Cross-Site Scripting (XSS) attacks</li>
                <li>Check authentication forms for weak session management</li>
                <li>Verify access controls on user-specific pages</li>
                <li>Test file upload functionality if present</li>
            </ol>
        </div>
        
        <div class="card" style="background: #f8f9fa; text-align: center;">
            <p>Generated by <strong>WebScanPro</strong> - Automated Web Application Security Scanner</p>
            <p>© 2024 Infosys Internship Project</p>
        </div>
    </div>
</body>
</html>'''
        
        with open('output/target_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] HTML report generated: output/target_report.html")