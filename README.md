WebScanPro – AI-Driven Web Application Security Testing Tool

• Overview

WebScanPro is an automated web application security testing framework designed to identify vulnerabilities aligned with the OWASP Top 10 standards. The tool integrates traditional security testing techniques with machine learning–based analysis to detect, classify, and prioritize security risks, generating comprehensive and actionable security reports.



• Key Capabilities

Automated discovery and analysis of web application attack surfaces

Detection of common web vulnerabilities using rule-based and AI-driven approaches

Session-aware crawling and authenticated scanning

Machine learning–assisted attack pattern recognition

Risk scoring and vulnerability prioritization

Professional security reporting in HTML, JSON, and PDF formats

• Technology Stack

Programming Language: Python 3.10+

Security & Web Libraries: Requests, BeautifulSoup4

Machine Learning: Scikit-learn

Containerization: Docker, Docker Compose

Target Application: DVWA (Damn Vulnerable Web Application)

Reporting: HTML, JSON, PDF

Development Environment: Visual Studio Code, Windows PowerShell

System Architecture

WEBSCANPRO
│
├── dashboard
│   ├── __pycache__
│   │   ├── ai_analyzer.cpython-312.pyc
│   │   ├── app.cpython-312.pyc
│   │   └── report_generator.cpython-312.pyc
│   │
│   ├── models
│   │   └── vulnerability_model.pkl
│   │
│   ├── static
│   │   ├── css
│   │   ├── js
│   │   └── style.css
│   │
│   ├── templates
│   │   ├── ai_report.html
│   │   ├── index.html
│   │   ├── json_findings.html
│   │   ├── reports.html
│   │   └── weekly_reports.html
│   │
│   ├── ai_analyzer.py
│   ├── app.py
│   ├── report_generator.py
│   │
│   └── generated_security_reports
│       └── security_report.pdf
│
├── logs
│
├── ml_logs
│   └── bruteforce_ml_logs.json
│
├── ml_models
│   ├── access_access_classifier.joblib
│   ├── access_escalation_detector.joblib
│   ├── access_idor_detector.joblib
│   ├── access_response_clusterer.joblib
│   ├── anomaly_detector.joblib
│   ├── attack_classifier.joblib
│   ├── text_vectorizer.joblib
│   └── time_clusterer.joblib
│
├── modules
│   ├── __pycache__
│   │   ├── access_control_tester.cpython-312.pyc
│   │   ├── auth_tester.cpython-312.pyc
│   │   ├── crawler.cpython-312.pyc
│   │   ├── scanner.cpython-312.pyc
│   │   ├── sqli_tester.cpython-312.pyc
│   │   └── xss_tester.cpython-312.pyc
│   │
│   ├── access_control_tester.py
│   ├── auth_tester.py
│   ├── crawler.py
│   ├── scanner.py
│   ├── sqli_tester.py
│   └── xss_tester.py
│
├── output
│   ├── access_control_report.html
│   ├── access_control_results.json
│   ├── auth_ml_report.html
│   ├── auth_ml_results.json
│   ├── auth_report.html
│   ├── auth_results.json
│   ├── bruteforce_logs.json
│   ├── crawl_results.json
│   ├── sqli_report.html
│   ├── sqli_results.json
│   ├── target_analysis.json
│   ├── target_report.html
│   ├── urls.txt
│   ├── week4_completed.txt
│   ├── week5_completed.txt
│   ├── week5_ml_completed.txt
│   ├── week6_completed.txt
│   ├── xss_report.html
│   └── xss_results.json
│
├── venv
│
├── .gitignore
├── config.py
├── docker-compose.yml
├── main.py
├── README.md
├── requirements_week6.txt
├── requirements.txt
├── requirementsd.txt
├── setup_week5.ps1
├── test_output.py
├── view_joblib_prediction.py
├── week3_sqli.py
├── week4_xss.py
├── week5_auth.py
└── week6_access_control.py


• Functional Modules
• Target Scanning and Intelligent Crawling Module

This module performs automated discovery of web application components. It crawls web pages recursively, identifies URLs, forms, and input fields, and maintains authenticated sessions where required. The output forms the baseline for subsequent vulnerability testing.

Key functionalities:

Session-aware crawling

URL and form discovery

Input field risk identification

Target surface mapping

• SQL Injection Testing Module

The SQL Injection module evaluates GET and POST parameters using multiple injection techniques. It identifies error-based, boolean-based, and time-based SQL injection vulnerabilities and classifies findings by severity.

Key functionalities:

Parameter tampering

Error pattern detection

Time-delay analysis

Severity classification and reporting

• Cross-Site Scripting (XSS) Testing Module

This module tests for reflected and form-based XSS vulnerabilities using a diverse payload library. It analyzes response content to detect script execution and payload reflection across multiple contexts.

Key functionalities:

Script, event-handler, and encoded payload testing

Reflection and context analysis

Payload categorization

Remediation recommendations

• Authentication and Session Security Testing Module

This module evaluates authentication mechanisms and session management practices. It simulates real-world attack scenarios such as weak credential usage, brute-force attempts, and session fixation.

AI/ML techniques are applied to identify abnormal authentication patterns and session anomalies.

Key functionalities:

Weak and default credential detection

Brute-force attack simulation

Session cookie flag analysis

ML-based anomaly detection

• Access Control and IDOR Testing Module

The access control module identifies authorization weaknesses, including horizontal and vertical privilege escalation. It also detects Insecure Direct Object Reference (IDOR) vulnerabilities using pattern-based and machine learning approaches.

Key functionalities:

Role-based access validation

Privilege escalation detection

IDOR vulnerability identification

ML-assisted response pattern classification

• AI-Driven Security Report Generation Module

This module aggregates results from all testing modules and applies machine learning and NLP techniques to classify vulnerabilities, assign risk scores, and generate executive-level insights.

Key functionalities:

Vulnerability aggregation and correlation

AI-based severity scoring

Automated mitigation suggestions

Interactive HTML dashboard and PDF reports

• Results Summary

Total vulnerabilities detected: 43

High-severity vulnerabilities identified: 43

Overall application risk score: 10 / 10

AI model confidence level: High

• Limitations

Testing primarily validated on DVWA

Limited support for modern JavaScript-heavy frameworks

Manual configuration required for target URLs

Coverage focused on OWASP Top 10 vulnerabilities

• Future Enhancements

Support for additional vulnerabilities such as CSRF, SSRF, XXE, and business logic flaws

Real-time adaptive scanning using reinforcement learning

CI/CD pipeline integration

REST API support for remote scanning

Web-based graphical user interface

Compliance-oriented reporting (GDPR, PCI-DSS, HIPAA)

Author

Sudharsan S
BCA – Artificial Intelligence and Machine Learning
VIT Vellore
Infosys Springboard Intern

GitHub Repository:
https://github.com/Sudhar0430/WebScanPro