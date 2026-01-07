

from typing import Dict  # Add this import
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
# Temporarily commented out problematic imports
# import pdfkit
# from weasyprint import HTML
import markdown
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
        
    def _create_custom_styles(self):
        """Create custom styles for the report"""
        self.styles['Heading1'].fontSize = 24
        self.styles['Heading1'].spaceAfter = 30
        self.styles['Heading1'].textColor = colors.HexColor('#2c3e50')
    
    # Modify existing Heading2 style  
        self.styles['Heading2'].fontSize = 18
        self.styles['Heading2'].spaceAfter = 12
        self.styles['Heading2'].textColor = colors.HexColor('#34495e')
    
    # Modify existing Normal style for body text
        self.styles['Normal'].fontSize = 11
        self.styles['Normal'].spaceAfter = 6
        
        
    def generate_pdf_report(self, analysis_data: Dict) -> str:
        """Generate professional PDF report using reportlab only"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.pdf"
        
        # Create PDF
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        story = []
        
        # Title
        story.append(Paragraph("AI-Powered Security Assessment Report", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        summary = analysis_data['executive_summary']
        story.append(Paragraph(f"Generated: {summary['generated_at']}", self.styles['BodyText']))
        story.append(Paragraph(f"AI Confidence: {summary['ai_model_confidence']}", self.styles['BodyText']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(summary['narrative'], self.styles['BodyText']))
        story.append(Paragraph(summary['recommendation'], self.styles['BodyText']))
        story.append(Spacer(1, 24))
        
        # Key Metrics
        story.append(Paragraph("Key Security Metrics", self.styles['Heading2']))
        metrics = summary['key_metrics']
        
        metrics_data = [
            ["Total Vulnerabilities", metrics['total_vulnerabilities']],
            ["Critical", metrics['critical_count']],
            ["High", metrics['high_count']],
            ["Medium", metrics['medium_count']],
            ["Low", metrics['low_count']],
            ["Average Risk Score", f"{metrics['average_risk_score']}/10"],
            ["Overall Risk Level", metrics['overall_risk_level']]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2*inch, 1*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 24))
        
        # Top Vulnerabilities
        story.append(Paragraph("Top Priority Vulnerabilities", self.styles['Heading2']))
        
        top_vulns = analysis_data['top_vulnerabilities']
        vuln_data = [["Type", "Severity", "Risk Score", "Endpoint"]]
        
        for vuln in top_vulns:
            vuln_data.append([
                vuln['type'],
                vuln['severity'],
                str(vuln['risk_score']),
                vuln['endpoint'][:50] + "..." if len(vuln['endpoint']) > 50 else vuln['endpoint']
            ])
        
        vuln_table = Table(vuln_data, colWidths=[1*inch, 1*inch, 1*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        
        story.append(vuln_table)
        story.append(Spacer(1, 24))
        
        # Recommendations
        story.append(Paragraph("AI-Generated Recommendations", self.styles['Heading2']))
        
        for i, vuln in enumerate(top_vulns[:3], 1):
            story.append(Paragraph(f"{i}. {vuln['type']} - {vuln['severity']}", self.styles['BodyText']))
            for mitigation in vuln['mitigations'][:2]:
                story.append(Paragraph(f"   • {mitigation}", self.styles['BodyText']))
            story.append(Spacer(1, 6))
        
        # Footer
        story.append(Spacer(1, 36))
        story.append(Paragraph("Generated by AI Security Dashboard", self.styles['BodyText']))
        story.append(Paragraph(f"Report ID: {timestamp}", self.styles['BodyText']))
        
        # Build PDF
        doc.build(story)
        
        return filename
    
    def generate_html_report(self, analysis_data: Dict) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .report-container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                .header {{ border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }}
                h1 {{ color: #2c3e50; margin: 0; }}
                h2 {{ color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
                .metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #3498db; }}
                .metric-value {{ font-size: 2em; font-weight: bold; margin: 10px 0; }}
                .critical {{ border-left-color: #e74c3c !important; }}
                .high {{ border-left-color: #e67e22 !important; }}
                .medium {{ border-left-color: #3498db !important; }}
                .low {{ border-left-color: #27ae60 !important; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; }}
                td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
                tr:nth-child(even) {{ background: #f9f9f9; }}
                .severity-critical {{ color: #e74c3c; font-weight: bold; }}
                .severity-high {{ color: #e67e22; font-weight: bold; }}
                .severity-medium {{ color: #3498db; font-weight: bold; }}
                .severity-low {{ color: #27ae60; font-weight: bold; }}
                .recommendation {{ background: #e8f4fc; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #3498db; }}
                .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #7f8c8d; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="report-container">
                <div class="header">
                    <h1>🔒 AI-Powered Security Assessment Report</h1>
                    <p>Generated: {analysis_data['executive_summary']['generated_at']}</p>
                    <p>Security Score: <strong>{analysis_data['security_score']}/100</strong></p>
                </div>
                
                <div class="executive-summary">
                    <h2>Executive Summary</h2>
                    <p>{analysis_data['executive_summary']['narrative']}</p>
                    <p><strong>Recommendation:</strong> {analysis_data['executive_summary']['recommendation']}</p>
                </div>
                
                <div class="metrics-grid">
                    <div class="metric-card critical">
                        <div class="metric-label">Critical Vulnerabilities</div>
                        <div class="metric-value">{analysis_data['executive_summary']['key_metrics']['critical_count']}</div>
                    </div>
                    <div class="metric-card high">
                        <div class="metric-label">High Severity</div>
                        <div class="metric-value">{analysis_data['executive_summary']['key_metrics']['high_count']}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Total Vulnerabilities</div>
                        <div class="metric-value">{analysis_data['executive_summary']['key_metrics']['total_vulnerabilities']}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Average Risk Score</div>
                        <div class="metric-value">{analysis_data['executive_summary']['key_metrics']['average_risk_score']}/10</div>
                    </div>
                </div>
                
                <h2>Top Priority Vulnerabilities</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Risk Score</th>
                            <th>Endpoint</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        # Add vulnerabilities
        for vuln in analysis_data['top_vulnerabilities']:
            severity_class = f"severity-{vuln['severity'].lower()}"
            html_content += f"""
                        <tr>
                            <td>{vuln['type']}</td>
                            <td class="{severity_class}">{vuln['severity']}</td>
                            <td>{vuln['risk_score']}</td>
                            <td><code>{vuln['endpoint'][:60]}{'...' if len(vuln['endpoint']) > 60 else ''}</code></td>
                            <td>{vuln['source_report']}</td>
                        </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
                
                <h2>AI-Generated Mitigation Steps</h2>
        """
        
        # Add mitigations
        for i, vuln in enumerate(analysis_data['top_vulnerabilities'][:5], 1):
            html_content += f"""
                <div class="recommendation">
                    <h3>{i}. {vuln['type']} - {vuln['severity']} Severity</h3>
                    <ul>
            """
            
            for mitigation in vuln['mitigations'][:3]:
                html_content += f"<li>{mitigation}</li>"
            
            html_content += """
                    </ul>
                </div>
            """
        
        # Footer
        html_content += f"""
                <div class="footer">
                    <p>Report generated by AI Security Dashboard v{analysis_data['ai_model_version']}</p>
                    <p>AI Model Confidence: {analysis_data['executive_summary']['ai_model_confidence']}</p>
                    <p>Report ID: {analysis_data['generated_at']}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save HTML file
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename