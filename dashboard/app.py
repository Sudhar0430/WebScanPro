#!/usr/bin/env python3
"""
AI-Powered Security Dashboard
Integrated vulnerability analysis and reporting system
"""

from flask import Flask, render_template, jsonify, send_file, request
import json
import os
import pandas as pd
from datetime import datetime, timedelta
from ai_analyzer import AIAnalyzer
from report_generator import ReportGenerator
from flask import send_from_directory
import plotly.graph_objects as go
import plotly.utils
import numpy as np

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

class SecurityDashboard:
    def __init__(self):
        self.output_dir = "../output" 
        self.ai_analyzer = AIAnalyzer()
        self.report_generator = ReportGenerator()
        
    def load_all_reports(self):
        """Load and aggregate all vulnerability reports"""
        reports = {
            'sqli': self._load_json('sqli_results.json'),
            'xss': self._load_json('xss_results.json'),
            'auth': self._load_json('auth_results.json'),
            'access_control': self._load_json('access_control_results.json'),
            'auth_ml': self._load_json('auth_ml_results.json'),
            'target_analysis': self._load_json('target_analysis.json')
        }
        return reports
    
    def _load_json(self, filename):
        """Load JSON file from output directory"""
        filepath = os.path.join(self.output_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return {}
    
    def generate_comprehensive_report(self):
        """Generate AI-powered comprehensive report"""
        reports = self.load_all_reports()
        return self.ai_analyzer.generate_comprehensive_analysis(reports)
    
    def _extract_report_summary(self, report_data):
        if not report_data or not isinstance(report_data, dict):
            return {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        vulnerabilities = report_data.get('vulnerabilities', [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
        summary = {
            'total': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                severity = vuln.get('severity', '').lower()
                if 'critical' in severity:
                    summary['critical'] += 1
                elif 'high' in severity:
                    summary['high'] += 1
                elif 'medium' in severity:
                    summary['medium'] += 1
                elif 'low' in severity:
                    summary['low'] += 1
        return summary

# Initialize global dashboard
print("Initializing Security Dashboard...")
try:
    dashboard = SecurityDashboard()
    print("✓ Security Dashboard initialized successfully")
except Exception as e:
    print(f"✗ Error initializing dashboard: {e}")
    dashboard = None

@app.route('/')
def index():
    """Main dashboard page"""
    reports = dashboard.load_all_reports()
    summary = dashboard.ai_analyzer.get_executive_summary(reports)
    
    # Generate charts data
    charts_data = dashboard.ai_analyzer.generate_charts_data(reports)
    
    return render_template('index.html', 
                         summary=summary,
                         charts_data=charts_data,
                         reports=reports)

@app.route('/reports')
def reports():
    """View all weekly reports"""
    try:
        dashboard = SecurityDashboard()  # Create new instance for this request
        reports_data = dashboard.load_all_reports()
        
        print(f"\n=== DEBUG: Reports Route ===")
        print(f"Output directory: {dashboard.output_dir}")
        print(f"Loaded {len(reports_data)} reports")
        
        # Process reports for template
        processed_reports = {}
        report_types = {
            'sqli_results': 'SQL Injection Scan',
            'xss_results': 'XSS Vulnerability Scan',
            'auth_results': 'Authentication Testing',
            'access_control_results': 'Access Control Testing',
            'auth_ml_results': 'Auth ML Analysis',
            'target_analysis': 'Target Analysis',
            'bruteforce_logs': 'Brute Force Logs'
        }
        
        for file_key, display_name in report_types.items():
            data = reports_data.get(file_key)
            
            # Debug print
            print(f"\n{display_name} ({file_key}):")
            print(f"  Data type: {type(data)}")
            
            # Get summary
            summary = dashboard._extract_report_summary(data)
            print(f"  Summary: {summary}")
            
            # Get vulnerabilities
            vulnerabilities = []
            if isinstance(data, dict):
                # Try different possible keys
                for key in ['vulnerabilities', 'vulns', 'findings']:
                    if key in data:
                        vulns = data[key]
                        if isinstance(vulns, list):
                            vulnerabilities = vulns
                        elif isinstance(vulns, dict):
                            vulnerabilities = [vulns]
                        break
                else:
                    # No vulnerabilities key found
                    if any(k in data for k in ['type', 'severity', 'description']):
                        vulnerabilities = [data]  # The dict itself is a vulnerability
            elif isinstance(data, list):
                vulnerabilities = data
            
            # Ensure it's a list
            if not isinstance(vulnerabilities, list):
                vulnerabilities = []
            
            processed_reports[display_name] = {
                'filename': file_key,
                'has_data': bool(data),
                'vulnerabilities': vulnerabilities[:5],  # Limit to 5 for display
                'summary': summary
            }
            
            print(f"  Vulnerabilities found: {len(vulnerabilities)}")
        
        print(f"\nTotal processed reports: {len(processed_reports)}")
        
        return render_template('reports.html', processed_reports=processed_reports)
        
    except Exception as e:
        print(f"\n=== ERROR in reports route ===")
        import traceback
        traceback.print_exc()
        
        # Fallback: show error page with sample data
        sample_data = {
            'SQL Injection Scan': {
                'filename': 'sqli_results.json',
                'has_data': False,
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
        }
        
        return render_template('reports.html', processed_reports=sample_data)
    
@app.route('/weekly-reports')
def weekly_reports():
    """Simple page to view weekly report HTML files"""
    return render_template('weekly_reports.html')

@app.route('/output-files/<path:filename>')
def serve_output_file(filename):
    """Serve files from the output directory via Flask"""
    # Get the absolute path to the output directory
    current_dir = os.path.dirname(os.path.abspath(__file__))  # dashboard folder
    output_dir = os.path.join(current_dir, '..', 'output')     # Go up one level to WebScanPro2/output
    
    print(f"DEBUG: Serving file '{filename}' from '{output_dir}'")
    
    # Check if directory exists
    if not os.path.exists(output_dir):
        print(f"ERROR: Output directory not found: {output_dir}")
        return f"Output directory not found: {output_dir}", 404
    
    # Check if file exists
    file_path = os.path.join(output_dir, filename)
    if not os.path.exists(file_path):
        print(f"ERROR: File not found: {file_path}")
        return f"File not found: {filename}", 404
    
    return send_from_directory(output_dir, filename)

@app.route('/ai-report')
def ai_report():
    """AI Analysis report page"""
    return render_template('ai_report.html')

@app.route('/api/ai-analysis')
def ai_analysis_data():
    """API endpoint for AI analysis data"""
    try:
        print("=== DEBUG: /api/ai-analysis called ===")
        
        # Use the global dashboard instance
        global dashboard
        
        # Load all reports using the global dashboard
        reports = dashboard.load_all_reports()
        print(f"DEBUG: Loaded {len(reports)} reports")
        
        # Debug: Check what's in reports
        total_vulns = 0
        for name, data in reports.items():
            if data:
                if isinstance(data, dict) and 'vulnerabilities' in data:
                    vuln_count = len(data['vulnerabilities'])
                    total_vulns += vuln_count
                    print(f"DEBUG: {name} -> {vuln_count} vulnerabilities")
                else:
                    print(f"DEBUG: {name} -> type: {type(data).__name__}, no vulnerabilities key")
            else:
                print(f"DEBUG: {name} -> EMPTY")
        
        print(f"DEBUG: Total vulnerabilities across all reports: {total_vulns}")
        
        if total_vulns == 0:
            print("DEBUG: No vulnerability data found, using enhanced sample data")
            return jsonify({
                'success': True,
                'analysis': get_enhanced_sample_analysis(),
                'timestamp': datetime.now().isoformat(),
                'ai_model': 'TF-IDF + Logistic Regression',
                'data_source': 'sample',
                'message': 'No vulnerability data found in scans'
            })
        
        # Generate AI analysis
        print("DEBUG: Generating AI analysis...")
        analysis = dashboard.ai_analyzer.generate_comprehensive_analysis(reports)
        print("DEBUG: AI analysis generated successfully")
        
        # Add debug info
        analysis['debug_info'] = {
            'reports_processed': len(reports),
            'total_vulnerabilities_found': total_vulns,
            'ai_model_used': 'TF-IDF + Logistic Regression'
        }
        
        return jsonify({
            'success': True,
            'analysis': analysis,
            'timestamp': datetime.now().isoformat(),
            'ai_model': 'TF-IDF + Logistic Regression',
            'data_source': 'real'
        })
        
    except Exception as e:
        print(f"ERROR in /api/ai-analysis: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e),
            'analysis': get_enhanced_sample_analysis(),
            'timestamp': datetime.now().isoformat(),
            'data_source': 'fallback'
        })

def get_enhanced_sample_analysis():
    """Return enhanced sample analysis data with realistic vulnerability patterns"""
    
    # Get current time for timestamps
    now = datetime.now()
    
    return {
        'executive_summary': {
            'narrative': 'AI security analysis completed. Critical vulnerabilities require immediate attention.',
            'recommendation': 'Prioritize SQL injection and XSS fixes. Implement security patches within 24 hours.',
            'key_metrics': {
                'total_vulnerabilities': 14,
                'critical_count': 3,
                'high_count': 5,
                'medium_count': 4,
                'low_count': 2,
                'average_risk_score': 7.8,
                'overall_risk_level': 'HIGH',
                'risk_color': 'danger'
            },
            'generated_at': now.strftime('%Y-%m-%d %H:%M:%S'),
            'ai_model_confidence': '96%'
        },
        'detailed_analysis': {
            'vulnerabilities': [
                {
                    'type': 'SQLi',
                    'original_type': 'SQL Injection',
                    'severity': 'Critical',
                    'risk_score': 9.7,
                    'description': 'SQL injection vulnerability in user login endpoint allowing authentication bypass',
                    'endpoint': '/api/v1/login',
                    'mitigations': [
                        'Use parameterized queries or prepared statements',
                        'Implement proper input validation',
                        'Apply principle of least privilege to database accounts'
                    ],
                    'source_report': 'sqli_results',
                    'timestamp': (now - timedelta(hours=2)).isoformat()
                },
                {
                    'type': 'XSS',
                    'original_type': 'Cross-Site Scripting',
                    'severity': 'High',
                    'risk_score': 8.2,
                    'description': 'Reflected XSS in search functionality allowing script execution',
                    'endpoint': '/search',
                    'mitigations': [
                        'Implement proper output encoding',
                        'Add Content Security Policy headers',
                        'Validate and sanitize all user inputs'
                    ],
                    'source_report': 'xss_results',
                    'timestamp': (now - timedelta(hours=4)).isoformat()
                },
                {
                    'type': 'Auth',
                    'original_type': 'Authentication Bypass',
                    'severity': 'Critical',
                    'risk_score': 9.3,
                    'description': 'Weak session management allows session hijacking',
                    'endpoint': '/api/session',
                    'mitigations': [
                        'Implement secure session tokens',
                        'Add proper session timeout',
                        'Use HTTPS for all authentication requests'
                    ],
                    'source_report': 'auth_results',
                    'timestamp': (now - timedelta(hours=1)).isoformat()
                },
                {
                    'type': 'Access',
                    'original_type': 'IDOR',
                    'severity': 'High',
                    'risk_score': 7.8,
                    'description': 'Insecure Direct Object Reference allows access to other user data',
                    'endpoint': '/api/users/{id}/profile',
                    'mitigations': [
                        'Implement proper access control checks',
                        'Use UUIDs instead of sequential IDs',
                        'Validate user permissions for each request'
                    ],
                    'source_report': 'access_control_results',
                    'timestamp': (now - timedelta(hours=3)).isoformat()
                }
            ],
            'summary': {
                'total_vulnerabilities': 14,
                'severity_distribution': {'Critical': 3, 'High': 5, 'Medium': 4, 'Low': 2},
                'average_risk_score': 7.8,
                'maximum_risk_score': 9.7,
                'overall_risk_level': 'HIGH',
                'risk_color': 'danger',
                'critical_count': 3,
                'high_count': 5,
                'medium_count': 4,
                'low_count': 2
            }
        },
        'charts_data': {
            'severity_distribution': {'Critical': 3, 'High': 5, 'Medium': 4, 'Low': 2},
            'type_distribution': {'SQLi': 4, 'XSS': 3, 'Auth': 3, 'Access': 2, 'Config': 2},
            'risk_scores': [9.7, 8.2, 9.3, 7.8, 6.5, 7.2, 8.9, 6.1, 7.5, 8.0, 5.9, 7.3, 6.8, 5.5],
            'timeline': {
                (now - timedelta(days=1)).strftime('%Y-%m-%d'): 3,
                now.strftime('%Y-%m-%d'): 11
            },
            'total_vulnerabilities': 14
        },
        'security_score': 62.5,
        'top_vulnerabilities': [
            {
                'type': 'SQLi',
                'severity': 'Critical',
                'risk_score': 9.7,
                'description': 'SQL injection vulnerability in user login endpoint',
                'endpoint': '/api/v1/login',
                'mitigations': ['Use parameterized queries', 'Implement input validation'],
                'source_report': 'sqli_results'
            },
            {
                'type': 'Auth',
                'severity': 'Critical',
                'risk_score': 9.3,
                'description': 'Weak session management allows session hijacking',
                'endpoint': '/api/session',
                'mitigations': ['Implement secure session tokens', 'Add session timeout'],
                'source_report': 'auth_results'
            },
            {
                'type': 'XSS',
                'severity': 'High',
                'risk_score': 8.2,
                'description': 'Reflected XSS in search functionality',
                'endpoint': '/search',
                'mitigations': ['Implement output encoding', 'Add CSP headers'],
                'source_report': 'xss_results'
            }
        ],
        'generated_at': now.isoformat(),
        'ai_model_version': '1.2.0',
        'ai_insights': [
            'SQL injection poses the highest risk due to potential data breach',
            'Authentication vulnerabilities require immediate attention',
            'Consider implementing a Web Application Firewall (WAF)',
            'Regular security training for developers recommended'
        ]
    }

@app.route('/api/ai-debug')
def ai_debug():
    """Debug endpoint for AI analyzer"""
    global dashboard
    
    debug_info = {
        'dashboard_exists': 'dashboard' in globals(),
        'dashboard_is_none': dashboard is None if 'dashboard' in globals() else 'N/A',
        'ai_analyzer_exists': hasattr(dashboard, 'ai_analyzer') if dashboard else False
    }
    
    # Test AI analyzer directly
    try:
        from ai_analyzer import AIAnalyzer
        test_analyzer = AIAnalyzer()
        test_result = test_analyzer.classify_vulnerability("SQL injection test")
        debug_info['direct_test'] = {
            'status': 'success',
            'result': test_result
        }
    except Exception as e:
        debug_info['direct_test'] = {
            'status': 'error',
            'error': str(e)
        }
    
    return jsonify(debug_info)

@app.route('/generate-pdf')
def generate_pdf():
    """Generate PDF report"""
    comprehensive_report = dashboard.generate_comprehensive_report()
    pdf_path = dashboard.report_generator.generate_pdf_report(comprehensive_report)
    return send_file(pdf_path, as_attachment=True)

@app.route('/api/dashboard-data')
def dashboard_data():
    """API endpoint for dashboard data"""
    reports = dashboard.load_all_reports()
    try:
        analysis = dashboard.ai_analyzer.analyze_vulnerabilities(reports)
        return jsonify(analysis)
    except Exception as e:
        print(f"Error in dashboard-data: {e}")
        # Return empty but valid structure
        return jsonify({
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'severity_distribution': {},
                'average_risk_score': 0,
                'overall_risk_level': 'LOW'
            }
        })

@app.route('/api/severity-distribution')
def severity_distribution():
    """API for severity distribution chart"""
    reports = dashboard.load_all_reports()
    distribution = dashboard.ai_analyzer.get_severity_distribution(reports)
    return jsonify(distribution)

@app.route('/api/vulnerability-trends')
def vulnerability_trends():
    """API for vulnerability trends"""
    reports = dashboard.load_all_reports()
    trends = dashboard.ai_analyzer.get_vulnerability_trends(reports)
    return jsonify(trends)

@app.route('/debug')
def debug():
    """Debug endpoint to check data flow"""
    reports = dashboard.load_all_reports()
    
    # Check what's actually loaded
    debug_info = {}
    for name, data in reports.items():
        debug_info[name] = {
            'exists': bool(data),
            'type': type(data).__name__,
        }
        if isinstance(data, dict):
            debug_info[name]['keys'] = list(data.keys())
            if 'vulnerabilities' in data:
                debug_info[name]['vuln_count'] = len(data['vulnerabilities'])
        elif isinstance(data, list):
            debug_info[name]['count'] = len(data)
    
    # Try AI analysis
    try:
        analysis = dashboard.ai_analyzer.analyze_vulnerabilities(reports)
        debug_info['analysis'] = {
            'success': True,
            'vuln_count': len(analysis.get('vulnerabilities', [])),
            'summary': analysis.get('summary', {})
        }
    except Exception as e:
        debug_info['analysis'] = {
            'success': False,
            'error': str(e)
        }
    
    return jsonify(debug_info)

@app.route('/check-files')
def check_files():
    """Check if output files exist"""
    import os
    
    dashboard = SecurityDashboard()
    files_info = {}
    
    expected_files = [
        'sqli_results.json', 'xss_results.json', 'auth_results.json',
        'access_control_results.json', 'auth_ml_results.json', 
        'target_analysis.json', 'bruteforce_logs.json'
    ]
    
    for filename in expected_files:
        filepath = os.path.join(dashboard.output_dir, filename)
        files_info[filename] = {
            'exists': os.path.exists(filepath),
            'path': filepath,
            'size': os.path.getsize(filepath) if os.path.exists(filepath) else 0
        }
    
    return jsonify(files_info)

@app.route('/debug-reports')
def debug_reports():
    """Debug endpoint for reports data"""
    reports = dashboard.load_all_reports()
    
    debug_info = {
        'total_reports': len(reports),
        'report_names': list(reports.keys()),
        'sample_report_data': {}
    }
    
    # Check each report structure
    for name, data in reports.items():
        if data:
            debug_info['sample_report_data'][name] = {
                'type': type(data).__name__,
                'has_vulnerabilities': 'vulnerabilities' in data if isinstance(data, dict) else False,
                'vuln_count': len(data.get('vulnerabilities', [])) if isinstance(data, dict) else 0
            }
    
    return jsonify(debug_info)

@app.route('/check-template')
def check_template():
    """Check if template files exist"""
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    print(f"Template directory: {template_dir}")
    
    templates = {}
    for filename in ['reports.html', 'index.html', 'ai_report.html']:
        path = os.path.join(template_dir, filename)
        templates[filename] = {
            'exists': os.path.exists(path),
            'path': path
        }
    
    return jsonify(templates)

@app.route('/raw-reports')
def raw_reports():
    """View raw report data"""
    reports = dashboard.load_all_reports()
    
    simplified = {}
    for name, data in reports.items():
        if isinstance(data, dict):
            simplified[name] = {
                'type': 'dict',
                'keys': list(data.keys()),
                'vuln_count': len(data.get('vulnerabilities', [])) if 'vulnerabilities' in data else 0
            }
            if data.get('vulnerabilities'):
                simplified[name]['sample'] = data['vulnerabilities'][0] if len(data['vulnerabilities']) > 0 else None
        elif isinstance(data, list):
            simplified[name] = {
                'type': 'list',
                'count': len(data),
                'sample': data[0] if len(data) > 0 else None
            }
        else:
            simplified[name] = {
                'type': type(data).__name__,
                'value': str(data)
            }
    
    return jsonify(simplified)

@app.route('/check-output')
def check_output():
    """Check if output directory and files exist"""
    import os
    import json
    
    dashboard = SecurityDashboard()
    result = {
        'output_dir': os.path.abspath(dashboard.output_dir),
        'dir_exists': os.path.exists(dashboard.output_dir),
        'files': []
    }
    
    if result['dir_exists']:
        expected_files = [
            'sqli_results.json', 'xss_results.json', 'auth_results.json',
            'access_control_results.json', 'auth_ml_results.json',
            'target_analysis.json', 'bruteforce_logs.json'
        ]
        
        for filename in expected_files:
            filepath = os.path.join(dashboard.output_dir, filename)
            file_info = {
                'filename': filename,
                'exists': os.path.exists(filepath),
                'path': filepath
            }
            
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        content = f.read().strip()
                        file_info['size'] = len(content)
                        file_info['not_empty'] = bool(content)
                        if content:
                            data = json.loads(content)
                            file_info['valid_json'] = True
                            file_info['type'] = type(data).__name__
                            if isinstance(data, dict):
                                file_info['keys'] = list(data.keys())
                            elif isinstance(data, list):
                                file_info['length'] = len(data)
                        else:
                            file_info['valid_json'] = False
                except Exception as e:
                    file_info['valid_json'] = False
                    file_info['error'] = str(e)
            
            result['files'].append(file_info)
    
    return jsonify(result)

@app.route('/json-findings')
def json_findings():
    """Page to view JSON scan findings"""
    return render_template('json_findings.html')

@app.route('/json-files/<path:filename>')
def serve_json_file(filename):
    """Serve JSON files from the output directory"""
    # Get the absolute path to the output directory
    current_dir = os.path.dirname(os.path.abspath(__file__))  # dashboard folder
    output_dir = os.path.join(current_dir, '..', 'output')     # Go up one level to WebScanPro2/output
    
    print(f"DEBUG: Serving JSON file '{filename}' from '{output_dir}'")
    
    # Check if directory exists
    if not os.path.exists(output_dir):
        print(f"ERROR: Output directory not found: {output_dir}")
        return jsonify({"error": f"Output directory not found: {output_dir}"}), 404
    
    # Check if file exists
    file_path = os.path.join(output_dir, filename)
    if not os.path.exists(file_path):
        print(f"ERROR: JSON file not found: {file_path}")
        return jsonify({"error": f"JSON file not found: {filename}"}), 404
    
    try:
        # Read and parse JSON file
        with open(file_path, 'r') as f:
            json_data = json.load(f)
        return jsonify(json_data)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {filename}: {e}")
        return jsonify({"error": f"Invalid JSON format in {filename}: {str(e)}"}), 400
    except Exception as e:
        print(f"ERROR: Failed to read {filename}: {e}")
        return jsonify({"error": f"Failed to read {filename}: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)