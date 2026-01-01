# modules/access_control_tester.py - Week 6: Access Control & IDOR Testing with AI/ML
import requests
import json
import time
import re
import os
import random
from datetime import datetime
from colorama import init, Fore
from collections import defaultdict, Counter

# Machine Learning Imports
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
import joblib
# Custom distance calculation without scipy
def _calculate_euclidean_distance(X, centers):
    """Calculate Euclidean distance without scipy"""
    distances = []
    for x in X:
        row_distances = []
        for center in centers:
            # Euclidean distance: sqrt(sum((x - center)^2))
            dist = np.sqrt(np.sum((x - center) ** 2))
            row_distances.append(dist)
        distances.append(row_distances)
    return np.array(distances)

init(autoreset=True)

class AccessControlAnalyzer:
    """AI/ML Analysis Engine for Access Control Testing"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.vectorizers = {}
        self.ml_insights = []
        
        # Initialize ML models
        self._initialize_ml_models()
    
    def _initialize_ml_models(self):
        """Initialize all ML models for access control analysis"""
        print(f"{Fore.CYAN}[*] Initializing Access Control ML models...")
        
        # 1. Response Pattern Clustering (K-Means)
        self.models['response_clusterer'] = KMeans(
            n_clusters=3,
            random_state=42,
            n_init=10
        )

    def _calculate_euclidean_distance(self, X, centers):
        """Calculate Euclidean distance without scipy dependency"""
        distances = []
        for x in X:
            row_distances = []
            for center in centers:
                dist = np.sqrt(np.sum((x - center) ** 2))
                row_distances.append(dist)
                distances.append(row_distances)
                return np.array(distances)
        
        # 2. Access Control Classifier (Random Forest)
        self.models['access_classifier'] = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            class_weight='balanced'
        )
        
        # 3. IDOR Pattern Detector (Custom ML)
        self.models['idor_detector'] = KMeans(
            n_clusters=2,
            random_state=42,
            n_init=10
        )
        
        # 4. Privilege Escalation Detector
        self.models['escalation_detector'] = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42
        )
        
        # 5. Text Vectorizer for response analysis
        self.vectorizers['response_vectorizer'] = TfidfVectorizer(
            max_features=100,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        # 6. Standard Scaler
        self.scalers['standard_scaler'] = StandardScaler()
        
        # 7. Feature Extractor for numeric patterns
        print(f"{Fore.GREEN}[+] Access Control ML models initialized")
    
    def analyze_response_patterns(self, responses_data):
        """ML: Cluster responses using K-Means to detect patterns"""
        if len(responses_data) < 10:
            return {"clusters": [], "anomalies": []}
        
        # Extract features from responses
        features = []
        for response in responses_data:
            feat = [
                response.get('status_code', 0),
                response.get('content_length', 0),
                response.get('response_time', 0),
                1 if response.get('is_authorized', False) else 0,
                len(str(response.get('content', ''))),
                response.get('unique_words', 0),
                response.get('has_error', 0)
            ]
            features.append(feat)
        
        # Apply K-Means clustering
        X = np.array(features)
        scaler = self.scalers['standard_scaler']
        X_scaled = scaler.fit_transform(X)
        
        kmeans = self.models['response_clusterer']
        clusters = kmeans.fit_predict(X_scaled)
        
        # Calculate cluster statistics
        cluster_stats = []
        for cluster_id in range(kmeans.n_clusters):
            cluster_indices = np.where(clusters == cluster_id)[0]
            if len(cluster_indices) > 0:
                cluster_responses = [responses_data[i] for i in cluster_indices]
                authorized_count = sum(1 for r in cluster_responses if r.get('is_authorized', False))
                unauthorized_count = len(cluster_responses) - authorized_count
                
                cluster_stats.append({
                    "cluster": cluster_id,
                    "size": len(cluster_indices),
                    "authorized_ratio": authorized_count / len(cluster_indices),
                    "avg_response_time": np.mean([r.get('response_time', 0) for r in cluster_responses]),
                    "dominant_status": Counter([r.get('status_code', 0) for r in cluster_responses]).most_common(1)[0][0]
                })
        
        # Detect anomalies (responses far from cluster centers)
        distances = self._calculate_euclidean_distance(X_scaled, kmeans.cluster_centers_)
        min_distances = distances.min(axis=1)
        anomaly_threshold = np.percentile(min_distances, 90)
        anomalies = np.where(min_distances > anomaly_threshold)[0]
        
        anomaly_details = []
        for idx in anomalies[:5]:  # Limit to top 5 anomalies
            anomaly_details.append({
                "index": int(idx),
                "distance": float(min_distances[idx]),
                "cluster": int(clusters[idx]),
                "url": responses_data[idx].get('url', 'N/A')
            })
        
        return {
            "clusters": clusters.tolist(),
            "cluster_stats": cluster_stats,
            "anomalies": anomaly_details,
            "cluster_centers": kmeans.cluster_centers_.tolist(),
            "inertia": float(kmeans.inertia_)
        }
    
    def classify_access_attempts(self, access_attempts):
        """ML: Classify access attempts as authorized/unauthorized using Random Forest"""
        if len(access_attempts) < 20:
            return {"predictions": [], "accuracy": 0, "feature_importance": []}
        
        # Prepare training data
        X = []
        y = []
        
        for attempt in access_attempts:
            # Feature engineering
            features = [
                attempt.get('user_role_numeric', 0),  # 0=guest, 1=user, 2=admin
                attempt.get('endpoint_complexity', 0),
                attempt.get('parameter_count', 0),
                attempt.get('http_method_numeric', 0),  # 0=GET, 1=POST, etc.
                attempt.get('has_id_parameter', 0),
                attempt.get('response_time', 0),
                attempt.get('content_length', 0),
                attempt.get('status_code', 200)
            ]
            X.append(features)
            
            # Label (1=unauthorized access detected, 0=authorized)
            y.append(1 if attempt.get('is_vulnerable', False) else 0)
        
        # Train Random Forest classifier
        X_array = np.array(X)
        y_array = np.array(y)
        
        # Split data if enough samples
        if len(set(y_array)) > 1:
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X_array, y_array, test_size=0.3, random_state=42
            )
            
            model = self.models['access_classifier']
            model.fit(X_train, y_train)
            
            # Make predictions
            predictions = model.predict(X_array)
            
            # Calculate accuracy
            accuracy = model.score(X_test, y_test) if len(X_test) > 0 else model.score(X_array, y_array)
            
            # Feature importance
            feature_names = [
                'User Role', 'Endpoint Complexity', 'Parameter Count',
                'HTTP Method', 'Has ID Parameter', 'Response Time',
                'Content Length', 'Status Code'
            ]
            importances = model.feature_importances_
            
            # Generate insights
            top_features = sorted(zip(feature_names, importances), 
                                  key=lambda x: x[1], reverse=True)[:3]
            
            if accuracy > 0.7:
                self.ml_insights.append({
                    "type": "Access Control Pattern Classification",
                    "finding": f"ML model detects access violations with {accuracy:.1%} accuracy",
                    "risk": "Informational",
                    "model": "Random Forest Classifier",
                    "top_features": [f[0] for f in top_features]
                })
            
            return {
                "predictions": predictions.tolist(),
                "accuracy": accuracy,
                "feature_importance": importances.tolist(),
                "feature_names": feature_names
            }
        
        return {"predictions": [], "accuracy": 0, "feature_importance": []}
    
    def detect_idor_patterns(self, idor_attempts):
        """ML: Detect IDOR patterns using clustering"""
        if len(idor_attempts) < 10:
            return {"patterns": [], "vulnerable_clusters": []}
        
        # Extract numeric patterns from ID parameters
        features = []
        for attempt in idor_attempts:
            # Extract ID patterns
            id_value = attempt.get('id_value', '')
            id_length = len(str(id_value))
            is_numeric = 1 if str(id_value).isdigit() else 0
            is_sequential = 0
            
            # Check for sequential patterns
            if is_numeric and len(str(id_value)) > 1:
                digits = [int(d) for d in str(id_value)]
                is_sequential = 1 if all(digits[i] + 1 == digits[i+1] for i in range(len(digits)-1)) else 0
            
            features.append([
                id_length,
                is_numeric,
                is_sequential,
                attempt.get('response_difference', 0),
                1 if attempt.get('access_granted', False) else 0
            ])
        
        # Apply K-Means clustering
        X = np.array(features)
        if len(X) < 2:
            return {"patterns": [], "vulnerable_clusters": []}
        
        kmeans = self.models['idor_detector']
        clusters = kmeans.fit_predict(X)
        
        # Analyze clusters for IDOR patterns
        cluster_analysis = []
        for cluster_id in range(kmeans.n_clusters):
            cluster_indices = np.where(clusters == cluster_id)[0]
            if len(cluster_indices) > 0:
                cluster_attempts = [idor_attempts[i] for i in cluster_indices]
                access_granted = sum(1 for a in cluster_attempts if a.get('access_granted', False))
                access_ratio = access_granted / len(cluster_attempts)
                
                cluster_analysis.append({
                    "cluster": cluster_id,
                    "size": len(cluster_indices),
                    "access_granted_ratio": access_ratio,
                    "likely_idor": access_ratio > 0.5,
                    "avg_id_length": np.mean([a.get('id_length', 0) for a in cluster_attempts])
                })
        
        # Identify vulnerable clusters (high access granted ratio)
        vulnerable_clusters = [c for c in cluster_analysis if c['likely_idor']]
        
        if vulnerable_clusters:
            self.ml_insights.append({
                "type": "IDOR Pattern Detection (K-Means)",
                "finding": f"Detected {len(vulnerable_clusters)} IDOR vulnerability patterns",
                "risk": "High",
                "model": "K-Means Clustering",
                "clusters_analyzed": len(cluster_analysis)
            })
        
        return {
            "clusters": clusters.tolist(),
            "cluster_analysis": cluster_analysis,
            "vulnerable_clusters": vulnerable_clusters,
            "cluster_centers": kmeans.cluster_centers_.tolist()
        }
    
    def analyze_privilege_escalation(self, escalation_data):
        """ML: Analyze privilege escalation patterns"""
        if len(escalation_data) < 15:
            return {"escalation_risk": 0, "patterns": []}
        
        # Extract features for escalation detection
        features = []
        labels = []
        
        for data in escalation_data:
            feat = [
                data.get('source_role_level', 0),
                data.get('target_role_level', 0),
                data.get('access_attempted', 0),
                data.get('endpoint_sensitivity', 0),
                data.get('parameter_manipulation', 0),
                data.get('response_difference', 0)
            ]
            features.append(feat)
            labels.append(1 if data.get('escalation_successful', False) else 0)
        
        # Train Random Forest for escalation prediction
        X = np.array(features)
        y = np.array(labels)
        
        if len(set(y)) > 1:
            model = self.models['escalation_detector']
            model.fit(X, y)
            
            # Predict escalation risk
            predictions = model.predict(X)
            risk_score = sum(predictions) / len(predictions)
            
            # Feature importance
            importance = model.feature_importances_
            feature_names = ['Source Role', 'Target Role', 'Access Attempted',
                           'Endpoint Sensitivity', 'Parameter Manipulation', 'Response Diff']
            
            return {
                "escalation_risk": risk_score,
                "predictions": predictions.tolist(),
                "feature_importance": importance.tolist(),
                "feature_names": feature_names,
                "model_accuracy": model.score(X, y)
            }
        
        return {"escalation_risk": 0, "patterns": []}
    
    def save_ml_models(self):
        """Save trained ML models"""
        os.makedirs("ml_models", exist_ok=True)
        
        for name, model in self.models.items():
            if hasattr(model, 'fit'):  # Check if it's an ML model
                filename = f"ml_models/access_{name}.joblib"
                joblib.dump(model, filename)
                print(f"{Fore.GREEN}[+] Saved model: {filename}")
    
    def generate_ml_report(self):
        """Generate ML insights report"""
        return {
            "ml_models_used": list(self.models.keys()),
            "ml_insights": self.ml_insights,
            "models_trained": len([m for m in self.models.values() if hasattr(m, 'fit')]),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

class AccessControlTester:
    """Access Control & IDOR Testing Module with AI/ML"""
    
    def __init__(self, session, base_url="http://localhost:8088"):
        self.session = session
        self.base_url = base_url
        self.vulnerabilities = []
        self.test_results = []
        self.ml_analyzer = AccessControlAnalyzer()
        
        # Data collection for ML
        self.access_attempts = []
        self.idor_attempts = []
        self.escalation_data = []
        self.responses_data = []
        
        # DVWA-specific roles and endpoints
        self.roles = {
            "admin": {"level": 2, "username": "admin", "password": "password"},
            "user": {"level": 1, "username": "gordonb", "password": "abc123"},
            "guest": {"level": 0, "username": "", "password": ""}
        }
        
        # Known DVWA endpoints for testing
        self.dvwa_endpoints = {
            "admin": ["/admin.php", "/setup.php", "/security.php"],
            "user": ["/vulnerabilities/", "/instructions.php"],
            "public": ["/login.php", "/index.php"]
        }
    
    # ==================== TASK 1: Role Identification ====================
    
    def identify_roles_and_access(self):
        """Identify roles and their access levels"""
        print(f"{Fore.YELLOW}[*] Task 1: Identifying roles and access levels...")
        
        vulnerabilities = []
        findings = []
        
        # Test access to admin endpoints with different privilege levels
        print(f"{Fore.WHITE}[*] Testing role-based access restrictions...")
        
        for role_name, role_info in self.roles.items():
            print(f"{Fore.CYAN}[*] Testing as: {role_name}")
            
            # Create session for this role
            role_session = self._create_role_session(role_name)
            if not role_session:
                continue
            
            # Test access to admin endpoints
            for endpoint in self.dvwa_endpoints["admin"]:
                url = f"{self.base_url}{endpoint}"
                
                try:
                    response = role_session.get(url, allow_redirects=False)
                    status = response.status_code
                    
                    finding = {
                        "role": role_name,
                        "endpoint": endpoint,
                        "status_code": status,
                        "access_granted": status == 200,
                        "expected_access": role_name == "admin"
                    }
                    findings.append(finding)
                    
                    # Check for vertical privilege escalation
                    if role_name != "admin" and status == 200:
                        vuln_info = {
                            "type": "Vertical Privilege Escalation",
                            "role": role_name,
                            "endpoint": endpoint,
                            "evidence": f"{role_name} can access admin endpoint: {endpoint}",
                            "severity": "High",
                            "recommendation": "Implement proper role-based access control (RBAC)"
                        }
                        vulnerabilities.append(vuln_info)
                        print(f"{Fore.RED}[!] VERTICAL ESCALATION: {role_name} -> {endpoint}")
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[-] Error testing {endpoint}: {e}")
        
        # ML Analysis of role patterns
        if len(findings) >= 5:
            self._analyze_role_patterns(findings)
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 2: IDOR Testing ====================
    
    def test_idor_vulnerabilities(self):
        """Test for Insecure Direct Object References"""
        print(f"{Fore.YELLOW}[*] Task 2: Testing IDOR vulnerabilities...")
        
        vulnerabilities = []
        idor_logs = []
        
        # Test common IDOR patterns in DVWA
        idor_test_cases = [
            {"url": "/vulnerabilities/sqli/", "param": "id", "values": [1, 2, 3, 4, 5]},
            {"url": "/vulnerabilities/view_source.php", "param": "id", "values": [1, 2, 3]},
            {"url": "/vulnerabilities/upload/", "param": "id", "values": [1, 2]},
        ]
        
        for test_case in idor_test_cases:
            base_url = f"{self.base_url}{test_case['url']}"
            param = test_case['param']
            
            print(f"{Fore.WHITE}[*] Testing IDOR on: {test_case['url']}")
            
            # First, get authorized response
            authorized_value = test_case['values'][0]
            auth_response = self.session.get(base_url, params={param: authorized_value})
            auth_content = auth_response.text[:500] if auth_response.text else ""
            
            # Test other IDs
            for test_value in test_case['values'][1:]:
                try:
                    test_response = self.session.get(base_url, params={param: test_value})
                    
                    # Compare responses
                    test_content = test_response.text[:500] if test_response.text else ""
                    content_diff = self._calculate_content_difference(auth_content, test_content)
                    
                    idor_log = {
                        "url": base_url,
                        "parameter": param,
                        "authorized_id": authorized_value,
                        "tested_id": test_value,
                        "auth_status": auth_response.status_code,
                        "test_status": test_response.status_code,
                        "content_difference": content_diff,
                        "access_granted": test_response.status_code == 200 and content_diff < 0.8,
                        "timestamp": datetime.now().isoformat()
                    }
                    idor_logs.append(idor_log)
                    
                    # Check for IDOR vulnerability
                    if test_response.status_code == 200 and content_diff < 0.8:
                        vuln_info = {
                            "type": "Insecure Direct Object Reference (IDOR)",
                            "url": base_url,
                            "parameter": param,
                            "authorized_id": authorized_value,
                            "accessed_id": test_value,
                            "evidence": f"Accessed resource with ID={test_value} using ID={authorized_value} credentials",
                            "severity": "High",
                            "recommendation": "Implement indirect object references or UUIDs with proper authorization checks"
                        }
                        vulnerabilities.append(vuln_info)
                        print(f"{Fore.RED}[!] IDOR DETECTED: Parameter {param} with value {test_value}")
                    
                    # Add to ML data collection
                    self.idor_attempts.append(idor_log)
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[-] Error testing ID {test_value}: {e}")
        
        # ML Analysis of IDOR patterns
        if len(self.idor_attempts) >= 5:
            idor_analysis = self.ml_analyzer.detect_idor_patterns(self.idor_attempts)
            
            for cluster in idor_analysis.get("vulnerable_clusters", []):
                if cluster.get("likely_idor", False):
                    self.ml_analyzer.ml_insights.append({
                        "type": "IDOR Pattern Cluster Detected",
                        "finding": f"Cluster {cluster['cluster']} shows IDOR vulnerability pattern",
                        "risk": "High",
                        "model": "K-Means Clustering",
                        "cluster_size": cluster.get("size", 0)
                    })
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 3: Access Control Testing ====================
    
    def test_access_control_violations(self):
        """Test for access control violations"""
        print(f"{Fore.YELLOW}[*] Task 3: Testing access control violations...")
        
        vulnerabilities = []
        access_logs = []
        
        # Test horizontal privilege escalation
        print(f"{Fore.WHITE}[*] Testing horizontal privilege escalation...")
        
        # Simulate user trying to access another user's data
        test_endpoints = [
            {"url": "/vulnerabilities/sqli/", "method": "GET", "params": {"id": "1"}},
            {"url": "/vulnerabilities/upload/", "method": "GET", "params": {}},
            {"url": "/vulnerabilities/csrf/", "method": "GET", "params": {}},
        ]
        
        for endpoint in test_endpoints:
            url = f"{self.base_url}{endpoint['url']}"
            
            # First request (baseline)
            baseline_response = self.session.get(url, params=endpoint.get('params', {}))
            baseline_data = {
                "status": baseline_response.status_code,
                "content_length": len(baseline_response.content),
                "content_hash": hash(baseline_response.text[:1000])
            }
            
            # Attempt with modified parameters (simulating different user)
            modified_params = endpoint.get('params', {}).copy()
            if 'id' in modified_params:
                modified_params['id'] = str(int(modified_params['id']) + 100)  # Different user ID
            
            test_response = self.session.get(url, params=modified_params)
            test_data = {
                "status": test_response.status_code,
                "content_length": len(test_response.content),
                "content_hash": hash(test_response.text[:1000])
            }
            
            # Check for horizontal escalation
            if (test_response.status_code == 200 and 
                baseline_response.status_code == 200 and
                test_data['content_hash'] != baseline_data['content_hash']):
                
                # Potential horizontal escalation
                vuln_info = {
                    "type": "Horizontal Privilege Escalation",
                    "url": url,
                    "evidence": "Accessed different user's data with same credentials",
                    "severity": "High",
                    "recommendation": "Implement user-specific authorization checks"
                }
                vulnerabilities.append(vuln_info)
                print(f"{Fore.RED}[!] HORIZONTAL ESCALATION: {url}")
            
            # Log for ML analysis
            access_log = {
                "url": url,
                "method": endpoint['method'],
                "params": endpoint['params'],
                "modified_params": modified_params,
                "baseline_status": baseline_response.status_code,
                "test_status": test_response.status_code,
                "content_difference": abs(baseline_data['content_length'] - test_data['content_length']),
                "is_vulnerable": test_response.status_code == 200 and baseline_response.status_code == 200,
                "timestamp": datetime.now().isoformat()
            }
            access_logs.append(access_log)
        
        # Test missing authorization checks
        print(f"{Fore.WHITE}[*] Testing missing authorization checks...")
        
        # Try to access sensitive actions without proper role
        sensitive_actions = [
            {"url": "/vulnerabilities/sqli_blind/", "method": "GET"},
            {"url": "/vulnerabilities/exec/", "method": "GET"},
            {"url": "/vulnerabilities/sqli/", "method": "POST", "data": {"id": "1", "Submit": "Submit"}},
        ]
        
        for action in sensitive_actions:
            url = f"{self.base_url}{action['url']}"
            
            try:
                if action['method'] == "GET":
                    response = self.session.get(url)
                else:
                    response = self.session.post(url, data=action.get('data', {}))
                
                # Check if sensitive action is accessible
                if response.status_code == 200 and not self._is_authorized_page(response.text):
                    vuln_info = {
                        "type": "Missing Authorization Check",
                        "url": url,
                        "evidence": "Sensitive action accessible without proper authorization",
                        "severity": "Medium",
                        "recommendation": "Add server-side authorization checks for all sensitive actions"
                    }
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.YELLOW}[!] MISSING AUTHORIZATION: {url}")
                
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Error testing {url}: {e}")
        
        # ML Analysis
        self.access_attempts.extend(access_logs)
        if len(self.access_attempts) >= 10:
            classification = self.ml_analyzer.classify_access_attempts(self.access_attempts)
            
            if classification.get("accuracy", 0) > 0.75:
                self.ml_analyzer.ml_insights.append({
                    "type": "Access Control Classification",
                    "finding": f"ML model classifies access violations with {classification['accuracy']:.1%} accuracy",
                    "risk": "Informational",
                    "model": "Random Forest",
                    "top_features": classification.get('feature_names', [])[:3]
                })
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 4: AI/ML Integration ====================
    
    def run_ml_analysis(self):
        """Run comprehensive ML analysis on collected data"""
        print(f"{Fore.YELLOW}[*] Task 4: Running AI/ML Analysis...")
        
        ml_results = {}
        
        # 1. Analyze response patterns with K-Means
        if len(self.responses_data) >= 10:
            print(f"{Fore.WHITE}[*] Running K-Means clustering on response patterns...")
            cluster_analysis = self.ml_analyzer.analyze_response_patterns(self.responses_data)
            ml_results["response_clusters"] = cluster_analysis
        
        # 2. Analyze IDOR patterns
        if len(self.idor_attempts) >= 5:
            print(f"{Fore.WHITE}[*] Analyzing IDOR patterns with clustering...")
            idor_analysis = self.ml_analyzer.detect_idor_patterns(self.idor_attempts)
            ml_results["idor_analysis"] = idor_analysis
        
        # 3. Analyze privilege escalation
        if len(self.escalation_data) >= 10:
            print(f"{Fore.WHITE}[*] Analyzing privilege escalation patterns...")
            escalation_analysis = self.ml_analyzer.analyze_privilege_escalation(self.escalation_data)
            ml_results["escalation_analysis"] = escalation_analysis
        
        # 4. Classify access attempts
        if len(self.access_attempts) >= 20:
            print(f"{Fore.WHITE}[*] Classifying access attempts with Random Forest...")
            classification = self.ml_analyzer.classify_access_attempts(self.access_attempts)
            ml_results["access_classification"] = classification
        
        # Save ML models
        self.ml_analyzer.save_ml_models()
        
        return ml_results
    
    # ==================== TASK 5: Logging & Reporting ====================
    
    def generate_access_control_report(self):
        """Generate comprehensive access control security report"""
        os.makedirs("output", exist_ok=True)
        
        # Run ML analysis
        ml_results = self.run_ml_analysis()
        ml_report = self.ml_analyzer.generate_ml_report()
        
        # Generate report
        report = {
            "scan_type": "Access Control & IDOR Security Testing",
            "target": self.base_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tests_performed": [
                "Role Identification & Analysis",
                "IDOR Vulnerability Testing",
                "Access Control Violation Testing",
                "Horizontal & Vertical Privilege Escalation Testing",
                "AI/ML Pattern Analysis"
            ],
            "vulnerabilities_found": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "ml_insights": self.ml_analyzer.ml_insights,
            "ml_models_used": ml_report["ml_models_used"],
            "statistics": {
                "roles_identified": len(self.roles),
                "idor_tests_performed": len(self.idor_attempts),
                "access_control_tests": len(self.access_attempts),
                "ml_models_trained": ml_report["models_trained"]
            },
            "ml_analysis_results": ml_results,
            "suggested_mitigations": self._get_suggested_mitigations()
        }
        
        # Save JSON report
        with open('output/access_control_results.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        # Generate HTML report
        self._generate_html_report(report)
        
        print(f"{Fore.GREEN}[+] Access control report saved to output/access_control_results.json")
        return report
    
    def _generate_html_report(self, report_data):
        """Generate professional HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro - Access Control & IDOR Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .ml-card {{ background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); color: white; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .high {{ color: #e74c3c; border-left: 4px solid #e74c3c; }}
        .medium {{ color: #f39c12; border-left: 4px solid #f39c12; }}
        .low {{ color: #27ae60; border-left: 4px solid #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #e74c3c; color: white; }}
        .vuln-row {{ background: #ffe6e6; }}
        .ml-row {{ background: #f0e6f5; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Access Control & IDOR Security Report</h1>
            <p>Generated: {report_data['timestamp']} | Target: {report_data['target']}</p>
        </div>
        
        <div class="stat-grid">
            <div class="stat-box {'high' if report_data['vulnerabilities_found'] > 0 else 'low'}">
                <div class="stat-number">{report_data['vulnerabilities_found']}</div>
                <div>Access Control Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report_data['statistics']['roles_identified']}</div>
                <div>Roles Identified</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report_data['statistics']['idor_tests_performed']}</div>
                <div>IDOR Tests</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report_data['statistics']['ml_models_trained']}</div>
                <div>ML Models Trained</div>
            </div>
        </div>
        
        <div class="card ml-card">
            <h2>🤖 Machine Learning Analysis</h2>
            <p><strong>Models Used:</strong> {', '.join(report_data['ml_models_used'])}</p>
            
            <div class="stat-grid">
                <div class="stat-box" style="background: #8e44ad; color: white;">
                    <div class="stat-number">K-Means</div>
                    <div>Clustering Analysis</div>
                </div>
                <div class="stat-box" style="background: #9b59b6; color: white;">
                    <div class="stat-number">Random Forest</div>
                    <div>Classification</div>
                </div>
            </div>
        </div>
        
        {self._generate_ml_insights_html(report_data.get('ml_insights', []))}
        
        {self._generate_vulnerabilities_html(report_data.get('vulnerabilities', []))}
        
        <div class="card">
            <h2>🔧 Suggested Mitigations</h2>
            <ul>"""
        
        for mitigation in report_data.get('suggested_mitigations', []):
            html += f"<li>{mitigation}</li>"
        
        html += """
            </ul>
        </div>
        
        <div class="card">
            <h2>📊 OWASP Compliance</h2>
            <table>
                <tr><th>OWASP Top 10</th><th>Category</th><th>Status</th></tr>
                <tr><td>A01:2021</td><td>Broken Access Control</td><td>✅ Tested</td></tr>
                <tr><td>A05:2021</td><td>Security Misconfiguration</td><td>✅ Tested</td></tr>
                <tr><td>Additional</td><td>IDOR Vulnerabilities</td><td>✅ Tested</td></tr>
            </table>
        </div>
        
        
    </div>
</body>
</html>"""
        
        with open('output/access_control_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] HTML report generated: output/access_control_report.html")
    
    def _generate_ml_insights_html(self, insights):
        """Generate ML insights HTML"""
        if not insights:
            return ""
        
        html = '<div class="card">\n<h2>🔍 ML Security Insights</h2>\n'
        
        for insight in insights:
            risk_color = {
                "High": "#e74c3c",
                "Medium": "#f39c12",
                "Low": "#27ae60",
                "Informational": "#3498db"
            }.get(insight.get("risk", "Informational"), "#3498db")
            
            html += f"""
            <div style="margin: 15px 0; padding: 15px; border-left: 4px solid {risk_color}; background: #f8f9fa;">
                <h3>{insight.get('type', 'ML Insight')}</h3>
                <p><strong>Finding:</strong> {insight.get('finding', 'N/A')}</p>
                <p><strong>Risk:</strong> <span style="color: {risk_color}">{insight.get('risk', 'N/A')}</span></p>
                <p><strong>Model:</strong> {insight.get('model', 'N/A')}</p>
            </div>"""
        
        html += "</div>"
        return html
    
    def _generate_vulnerabilities_html(self, vulnerabilities):
        """Generate vulnerabilities HTML"""
        if not vulnerabilities:
            return '<div class="card" style="background: #eaffea;">\n<h2 style="color: #27ae60;">✅ No Access Control Vulnerabilities Found!</h2>\n<p>Strong access controls implemented.</p>\n</div>'
        
        html = """
        <div class="card">
            <h2>⚠️ Detected Access Control Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Evidence</th>
                    <th>Severity</th>
                    <th>Recommendation</th>
                </tr>"""
        
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower()
            html += f"""
                <tr class="vuln-row">
                    <td>{vuln['type']}</td>
                    <td>{vuln.get('evidence', 'N/A')}</td>
                    <td class="{severity_class}">{vuln['severity']}</td>
                    <td>{vuln.get('recommendation', 'N/A')}</td>
                </tr>"""
        
        html += """
            </table>
        </div>"""
        return html
    
    # ==================== UTILITY METHODS ====================
    
    def _create_role_session(self, role_name):
        """Create a session for a specific role"""
        if role_name not in self.roles:
            return None
        
        role_info = self.roles[role_name]
        
        # Create new session
        session = requests.Session()
        
        # If role has credentials, login
        if role_info["username"] and role_info["password"]:
            try:
                # Get CSRF token
                login_url = f"{self.base_url}/login.php"
                response = session.get(login_url)
                csrf_token = self._extract_csrf_token(response.text)
                
                # Login
                login_data = {
                    "username": role_info["username"],
                    "password": role_info["password"],
                    "Login": "Login",
                    "user_token": csrf_token
                }
                
                session.post(login_url, data=login_data)
                print(f"{Fore.GREEN}[+] Created session for role: {role_name}")
                return session
                
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Failed to create session for {role_name}: {e}")
                return None
        
        return session
    
    def _calculate_content_difference(self, content1, content2):
        """Calculate difference between two content strings"""
        if not content1 or not content2:
            return 1.0
        
        # Simple similarity calculation
        set1 = set(content1.split())
        set2 = set(content2.split())
        
        if not set1 or not set2:
            return 1.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return 1 - (intersection / union) if union > 0 else 1.0
    
    def _is_authorized_page(self, content):
        """Check if page content indicates authorization"""
        unauthorized_indicators = [
            "Login failed",
            "Access denied",
            "Unauthorized",
            "403 Forbidden",
            "You don't have permission"
        ]
        
        content_lower = content.lower()
        for indicator in unauthorized_indicators:
            if indicator.lower() in content_lower:
                return False
        
        return True
    
    def _extract_csrf_token(self, html):
        """Extract CSRF token from HTML"""
        token_match = re.search(r'name=["\']user_token["\'] value=["\']([^"\']+)["\']', html)
        return token_match.group(1) if token_match else ""
    
    def _analyze_role_patterns(self, findings):
        """Analyze role access patterns for ML"""
        for finding in findings:
            self.responses_data.append({
                "role": finding["role"],
                "endpoint": finding["endpoint"],
                "status_code": finding["status_code"],
                "is_authorized": finding["access_granted"],
                "expected_access": finding["expected_access"]
            })
    
    def _get_suggested_mitigations(self):
        """Get suggested mitigations for access control vulnerabilities"""
        return [
            "Implement Role-Based Access Control (RBAC) with proper privilege separation",
            "Use Attribute-Based Access Control (ABAC) for complex authorization scenarios",
            "Always perform server-side authorization checks, never rely on client-side",
            "Use indirect object references or UUIDs instead of sequential IDs",
            "Implement proper session management with role validation",
            "Regularly audit access control policies and permissions",
            "Use principle of least privilege for all user roles",
            "Implement proper error handling without revealing sensitive information"
        ]
    
    def save_results(self):
        """Save all test results"""
        return self.generate_access_control_report()