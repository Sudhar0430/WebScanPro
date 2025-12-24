#!/usr/bin/env python3
"""
AI-Powered Security Dashboard
Integrated vulnerability analysis and reporting system
"""

from flask import Flask, render_template, jsonify, send_file, request
import json
import os
import pandas as pd
from datetime import datetime
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
                    
dashboard = SecurityDashboard()

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
    """Generate AI-powered comprehensive report"""
    comprehensive_report = dashboard.generate_comprehensive_report()
    return render_template('ai_report.html', report=comprehensive_report)



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
    analysis = dashboard.ai_analyzer.analyze_vulnerabilities(reports)
    return jsonify(analysis)

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
# Add this route to app.py after your existing routes
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)