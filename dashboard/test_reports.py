# test_reports.py
import sys
import os
sys.path.append('.')

from app import SecurityDashboard

dashboard = SecurityDashboard()
reports = dashboard.load_all_reports()

print(f"Total reports loaded: {len(reports)}")
print("\nReport Details:")
for name, data in reports.items():
    print(f"\n{name}:")
    print(f"  Has data: {bool(data)}")
    if data and isinstance(data, dict):
        vulns = data.get('vulnerabilities', [])
        print(f"  Vulnerabilities: {len(vulns)}")
        if vulns:
            print(f"  Sample: {vulns[0].get('type', 'Unknown')} - {vulns[0].get('description', 'No desc')[:50]}...")