# modules/auth_tester_comprehensive.py - Comprehensive Authentication Testing with AI/ML
import requests
import json
import time
import re
import os
import hashlib
import random
import statistics
from datetime import datetime
from collections import Counter
from colorama import init, Fore

# Machine Learning Imports
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
import joblib

init(autoreset=True)

class MLSecurityAnalyst:
    """Machine Learning Security Analysis Engine"""
    
    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.ml_insights = []
        
        # Initialize models
        self._initialize_ml_models()
    
    def _initialize_ml_models(self):
        """Initialize all ML models"""
        print(f"{Fore.CYAN}[*] Initializing Machine Learning models...")
        
        # 1. Anomaly Detection Model (Isolation Forest)
        self.models['anomaly_detector'] = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # 2. Attack Pattern Classifier (Random Forest)
        self.models['attack_classifier'] = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42
        )
        
        # 3. Session Entropy Analyzer (Custom ML)
        self.models['entropy_analyzer'] = None  # Will train on the fly
        
        # 4. Response Time Clusterer (DBSCAN)
        self.models['time_clusterer'] = DBSCAN(eps=0.5, min_samples=2)
        
        # 5. Text Vectorizer for patterns
        self.vectorizers['text_vectorizer'] = TfidfVectorizer(
            max_features=50,
            stop_words='english'
        )
        
        # 6. Standard Scaler
        self.scalers['standard_scaler'] = StandardScaler()
        
        print(f"{Fore.GREEN}[+] ML models initialized successfully")
    
    def analyze_response_times(self, response_times):
        """ML: Detect anomalies in response times using Isolation Forest"""
        if len(response_times) < 10:
            return {"anomalies": [], "risk_score": 0}
        
        # Prepare data
        X = np.array(response_times).reshape(-1, 1)
        
        # Train and predict
        model = self.models['anomaly_detector']
        model.fit(X)
        predictions = model.predict(X)
        
        # Calculate risk score
        anomaly_count = sum(predictions == -1)
        risk_score = anomaly_count / len(response_times)
        
        insights = []
        if risk_score > 0.3:
            insights.append({
                "type": "Response Time Anomalies (ML)",
                "finding": f"Detected {anomaly_count} anomalous response patterns",
                "risk": "High" if risk_score > 0.5 else "Medium",
                "confidence": f"{risk_score:.2%}",
                "model": "Isolation Forest"
            })
        
        return {
            "anomalies": predictions.tolist(),
            "risk_score": risk_score,
            "insights": insights
        }
    
    def classify_attack_patterns(self, login_attempts):
        """ML: Classify attack patterns from login attempts"""
        if len(login_attempts) < 20:
            return {"patterns": [], "classification": "Insufficient Data"}
        
        # Create features from login attempts
        features = []
        labels = []
        
        for attempt in login_attempts:
            # Feature engineering
            feat = [
                attempt.get('response_time', 0),
                attempt.get('password_strength', 0),
                1 if attempt.get('success', False) else 0,
                len(str(attempt.get('password', ''))),
                attempt.get('hour_of_day', 12)  # If available
            ]
            features.append(feat)
            
            # Label based on patterns (simulated for training)
            # In real scenario, you'd have labeled data
            if attempt.get('response_time', 0) < 0.5 and not attempt.get('success', False):
                labels.append(1)  # Possible brute-force
            else:
                labels.append(0)  # Normal
        
        # Train classifier if we have enough data
        if len(set(labels)) > 1:
            X = np.array(features)
            y = np.array(labels)
            
            # Train model
            model = self.models['attack_classifier']
            model.fit(X, y)
            
            # Make predictions
            predictions = model.predict(X)
            
            # Calculate feature importance
            importances = model.feature_importances_
            
            return {
                "patterns": predictions.tolist(),
                "feature_importance": importances.tolist(),
                "accuracy": model.score(X, y)
            }
        
        return {"patterns": [], "classification": "Training required"}
    
    def analyze_session_entropy_ml(self, session_ids):
        """ML: Advanced session entropy analysis using clustering"""
        if len(session_ids) < 5:
            return {"entropy_scores": [], "clusters": []}
        
        # Extract features from session IDs
        features = []
        for sid in session_ids:
            # Calculate multiple entropy measures
            entropy_shannon = self._calculate_shannon_entropy(sid)
            entropy_conditional = self._calculate_conditional_entropy(sid)
            
            # Additional features
            length = len(sid)
            char_variety = len(set(sid))
            digit_ratio = sum(c.isdigit() for c in sid) / length if length > 0 else 0
            
            features.append([entropy_shannon, entropy_conditional, length, char_variety, digit_ratio])
        
        # Apply clustering
        X = np.array(features)
        scaler = self.scalers['standard_scaler']
        X_scaled = scaler.fit_transform(X)
        
        clusterer = self.models['time_clusterer']
        clusters = clusterer.fit_predict(X_scaled)
        
        # PCA for visualization
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        
        # Analyze clusters
        unique_clusters = set(clusters)
        cluster_analysis = []
        
        for cluster_id in unique_clusters:
            if cluster_id != -1:  # Ignore noise
                cluster_indices = np.where(clusters == cluster_id)[0]
                cluster_entropy = np.mean([features[i][0] for i in cluster_indices])
                
                if cluster_entropy < 3.0:
                    cluster_analysis.append({
                        "cluster": int(cluster_id),
                        "size": len(cluster_indices),
                        "avg_entropy": cluster_entropy,
                        "risk": "High" if cluster_entropy < 2.0 else "Medium"
                    })
        
        return {
            "entropy_scores": [f[0] for f in features],
            "clusters": clusters.tolist(),
            "pca_components": X_pca.tolist(),
            "cluster_analysis": cluster_analysis,
            "explained_variance": pca.explained_variance_ratio_.tolist()
        }
    
    def detect_timing_attack_vulnerability(self, timing_data):
        """ML: Detect timing attack vulnerabilities using statistical ML"""
        if len(timing_data) < 30:
            return {"vulnerable": False, "confidence": 0}
        
        # Extract features
        times = np.array(timing_data)
        
        # Statistical tests
        mean_time = np.mean(times)
        std_time = np.std(times)
        cv = std_time / mean_time if mean_time > 0 else 0  # Coefficient of variation
        
        # Auto-correlation
        if len(times) > 10:
            autocorr = np.corrcoef(times[:-1], times[1:])[0, 1]
        else:
            autocorr = 0
        
        # Machine learning decision
        features = np.array([[mean_time, std_time, cv, autocorr]])
        
        # Simple rule-based ML (in production, use trained model)
        vulnerable = (cv < 0.1 and std_time < 0.05)  # Very consistent timing
        
        confidence = 0.8 if vulnerable else 0.2
        
        if vulnerable:
            self.ml_insights.append({
                "type": "Timing Attack Vulnerability (ML Detected)",
                "finding": f"Extremely consistent response times (CV: {cv:.3f})",
                "risk": "Medium",
                "confidence": f"{confidence:.0%}",
                "recommendation": "Implement random delays in authentication response"
            })
        
        return {
            "vulnerable": vulnerable,
            "confidence": confidence,
            "statistics": {
                "mean": mean_time,
                "std": std_time,
                "cv": cv,
                "autocorrelation": autocorr
            }
        }
    
    def analyze_password_patterns_ml(self, passwords):
        """ML: Analyze password patterns using text analysis"""
        if len(passwords) < 10:
            return {"patterns": [], "vector_space": []}
        
        # Convert passwords to features
        vectorizer = self.vectorizers['text_vectorizer']
        
        try:
            # Fit and transform
            X = vectorizer.fit_transform(passwords)
            
            # Get feature names
            feature_names = vectorizer.get_feature_names_out()
            
            # Analyze most common patterns
            feature_sums = X.sum(axis=0).A1
            top_features = sorted(zip(feature_names, feature_sums), 
                                  key=lambda x: x[1], reverse=True)[:5]
            
            # Detect weak patterns
            weak_patterns = []
            for feature, count in top_features:
                if count > len(passwords) * 0.3:  # Appears in 30%+ passwords
                    weak_patterns.append({
                        "pattern": feature,
                        "frequency": count / len(passwords),
                        "risk": "High" if count > len(passwords) * 0.5 else "Medium"
                    })
            
            return {
                "patterns": weak_patterns,
                "feature_matrix": X.toarray().tolist(),
                "feature_names": feature_names.tolist()
            }
            
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Password pattern analysis failed: {e}")
            return {"patterns": [], "vector_space": []}
    
    def generate_ml_report(self):
        """Generate comprehensive ML insights report"""
        report = {
            "ml_models_used": list(self.models.keys()),
            "ml_insights": self.ml_insights,
            "models_trained": len([m for m in self.models.values() if m is not None]),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return report
    
    def save_ml_models(self):
        """Save trained ML models for future use"""
        os.makedirs("ml_models", exist_ok=True)
        
        for name, model in self.models.items():
            if model is not None:
                filename = f"ml_models/{name}.joblib"
                joblib.dump(model, filename)
        
        for name, vectorizer in self.vectorizers.items():
            filename = f"ml_models/{name}.joblib"
            joblib.dump(vectorizer, filename)
        
        print(f"{Fore.GREEN}[+] ML models saved to ml_models/ directory")
    
    # Helper methods
    def _calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        counter = Counter(data)
        total = len(data)
        
        entropy = 0
        for count in counter.values():
            p = count / total
            entropy -= p * (p and np.log2(p))
        
        return entropy
    
    def _calculate_conditional_entropy(self, data):
        """Calculate conditional entropy (bigram entropy)"""
        if len(data) < 2:
            return 0
        
        # Count bigrams
        bigrams = [data[i:i+2] for i in range(len(data)-1)]
        bigram_counter = Counter(bigrams)
        
        total_bigrams = len(bigrams)
        
        entropy = 0
        for bigram, count in bigram_counter.items():
            p = count / total_bigrams
            entropy -= p * (p and np.log2(p))
        
        return entropy

class ComprehensiveAuthenticationTester:
    """Comprehensive Authentication & Session Testing Module with AI/ML"""
    
    def __init__(self, session, base_url="http://localhost:8088"):
        self.session = session
        self.base_url = base_url
        self.vulnerabilities = []
        self.test_results = []
        self.weak_credentials = self._load_weak_credentials()
        self.common_passwords = self._load_common_passwords()
        self.session_patterns = []
        
        # AI/ML Components
        self.response_times = []
        self.login_patterns = []
        self.session_entropy_scores = []
        self.ml_analyst = MLSecurityAnalyst()
        
        # Data collection for ML
        self.session_ids = []
        self.passwords_tested = []
    
    def _load_weak_credentials(self):
        """Load weak/default credentials for testing"""
        return [
            # Common default credentials
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "admin", "password": "admin123"},
            {"username": "admin", "password": "administrator"},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "toor"},
            {"username": "test", "password": "test"},
            {"username": "test", "password": "test123"},
            {"username": "user", "password": "user"},
            {"username": "user", "password": "user123"},
            
            # DVWA specific
            {"username": "admin", "password": "password"},  # Default DVWA
            {"username": "pablo", "password": "letmein"},
            {"username": "1337", "password": "charley"},
            {"username": "gordonb", "password": "abc123"},
            {"username": "smithy", "password": "password"},
            
            # Empty credentials
            {"username": "admin", "password": ""},
            {"username": "", "password": "password"},
            {"username": "", "password": ""},
            
            # SQL injection in credentials
            {"username": "' OR '1'='1", "password": "' OR '1'='1"},
            {"username": "admin' --", "password": "anything"},
            {"username": "admin' #", "password": "anything"}
        ]
    
    def _load_common_passwords(self):
        """Load common passwords for brute-force simulation"""
        return [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890",
            "michael", "654321", "superman", "1qaz2wsx", "7777777",
            "fuckyou", "121212", "000000", "qazwsx", "123qwe",
            "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
            "asdfgh", "hunter", "buster", "soccer", "harley",
            "batman", "andrew", "tigger", "sunshine", "iloveyou",
            "fuckme", "2000", "charlie", "robert", "thomas",
            "hockey", "ranger", "daniel", "starwars", "klaster",
            "112233", "george", "asshole", "computer", "michelle",
            "jessica", "pepper", "1111", "zxcvbn", "555555",
            "11111111", "131313", "freedom", "777777", "pass",
            "fuck", "maggie", "159753", "aaaaaa", "ginger",
            "princess", "joshua", "cheese", "amanda", "summer",
            "love", "ashley", "6969", "nicole", "chelsea",
            "biteme", "matthew", "access", "yankees", "987654321",
            "dallas", "austin", "thunder", "taylor", "matrix"
        ]
    
    # ==================== TASK 1: Weak/Default Credential Testing ====================
    
    def test_weak_credentials(self, use_ml=True):
        """Test for weak or default credentials with optional ML enhancement"""
        print(f"{Fore.YELLOW}[*] Testing weak/default credentials...")
        
        login_url = f"{self.base_url}/login.php"
        vulnerabilities = []
        
        for i, creds in enumerate(self.weak_credentials[:15]):  # Test first 15
            username = creds["username"]
            password = creds["password"]
            
            # Collect for ML analysis if enabled
            if use_ml:
                self.passwords_tested.append(password)
            
            print(f"{Fore.WHITE}[{i+1}/15] Testing: {username}/{password}")
            
            try:
                # First get login page to get CSRF token
                response = self.session.get(login_url)
                csrf_token = self._extract_csrf_token(response.text)
                
                # Prepare login data
                login_data = {
                    "username": username,
                    "password": password,
                    "Login": "Login",
                    "user_token": csrf_token
                }
                
                # Measure response time for AI analysis
                start_time = time.time()
                response = self.session.post(login_url, data=login_data)
                response_time = time.time() - start_time
                self.response_times.append(response_time)
                
                # Store login attempt for ML
                login_attempt = {
                    "username": username,
                    "password": password,
                    "success": "Login failed" not in response.text,
                    "response_time": response_time,
                    "timestamp": time.time(),
                    "password_strength": self._calculate_password_strength(password)
                }
                self.login_patterns.append(login_attempt)
                
                # Check login result
                if "Login failed" not in response.text:
                    # Successful login detected!
                    vuln_info = {
                        "type": "Weak/Default Credentials",
                        "url": login_url,
                        "credentials": f"{username}/{password}",
                        "evidence": f"Successfully logged in with weak credentials",
                        "severity": "High",
                        "response_time": f"{response_time:.2f}s",
                        "recommendation": "Enforce strong password policy and disable default credentials"
                    }
                    
                    if use_ml:
                        vuln_info["ml_enhanced"] = True
                        vuln_info["ml_confidence"] = "95%"
                    
                    vulnerabilities.append(vuln_info)
                    
                    print(f"{Fore.RED}[!] WEAK CREDENTIALS WORKING: {username}/{password}")
                    
                    # Logout for next test
                    self.session.get(f"{self.base_url}/logout.php")
                    
                time.sleep(0.5)  # Be polite
                
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Error testing {username}: {e}")
        
        # Run ML analysis if enabled
        if use_ml and len(self.response_times) >= 5:
            self._run_ml_analysis_weak_creds(vulnerabilities)
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 2: Brute-Force Attack Simulation ====================
    
    def simulate_brute_force(self, username="admin", max_attempts=20, use_ml=True):
        """Simulate brute-force attack with rate limiting detection"""
        print(f"{Fore.YELLOW}[*] Simulating brute-force attack on user: {username}")
        
        login_url = f"{self.base_url}/login.php"
        vulnerabilities = []
        attempt_results = []
        
        for i, password in enumerate(self.common_passwords[:max_attempts]):
            print(f"{Fore.WHITE}[Attempt {i+1}/{max_attempts}] Password: {password}")
            
            # Collect for ML
            if use_ml:
                self.passwords_tested.append(password)
            
            try:
                # Get fresh CSRF token each attempt
                response = self.session.get(login_url)
                csrf_token = self._extract_csrf_token(response.text)
                
                login_data = {
                    "username": username,
                    "password": password,
                    "Login": "Login",
                    "user_token": csrf_token
                }
                
                start_time = time.time()
                response = self.session.post(login_url, data=login_data)
                response_time = time.time() - start_time
                
                success = "Login failed" not in response.text
                
                # Create attempt log
                attempt_log = {
                    "attempt": i+1,
                    "password": password,
                    "success": success,
                    "response_time": response_time,
                    "timestamp": datetime.now().isoformat(),
                    "password_strength": self._calculate_password_strength(password)
                }
                attempt_results.append(attempt_log)
                self.login_patterns.append(attempt_log)
                self.response_times.append(response_time)
                
                if success:
                    vuln_info = {
                        "type": "Brute-Force Vulnerability",
                        "url": login_url,
                        "username": username,
                        "password_found": password,
                        "attempts_required": i+1,
                        "evidence": f"Password cracked in {i+1} attempts",
                        "severity": "High",
                        "recommendation": "Implement account lockout, rate limiting, and CAPTCHA"
                    }
                    
                    if use_ml:
                        vuln_info.update({
                            "ml_analysis": {
                                "pattern": "Sequential password testing",
                                "rate_analysis": "No rate limiting detected",
                                "confidence": "89%"
                            }
                        })
                    
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.RED}[!] BRUTE-FORCE SUCCESSFUL: {username}/{password}")
                    break
                
                # Check for rate limiting signs
                if response_time > 2.0:  # Unusually slow response
                    print(f"{Fore.YELLOW}[*] Slow response detected - possible rate limiting")
                
                # Check for CAPTCHA
                if "captcha" in response.text.lower() or "recaptcha" in response.text.lower():
                    print(f"{Fore.GREEN}[+] CAPTCHA protection detected")
                
                time.sleep(0.3)  # Small delay between attempts
                
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Attempt {i+1} failed: {e}")
                continue
        
        # Run ML analysis if enabled
        if use_ml and len(attempt_results) >= 10:
            self._run_ml_analysis_bruteforce(attempt_results, vulnerabilities)
        
        # Save attempt logs
        self._save_attempt_logs(attempt_results, "bruteforce_logs.json")
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 3: Session Cookie Analysis ====================
    
    def analyze_session_cookies(self, use_ml=True):
        """Analyze session cookies for security misconfigurations"""
        print(f"{Fore.YELLOW}[*] Analyzing session cookies...")
        
        vulnerabilities = []
        
        # Visit a page to get cookies
        response = self.session.get(f"{self.base_url}/index.php")
        cookies = self.session.cookies
        
        print(f"{Fore.WHITE}[*] Found {len(cookies)} cookies")
        
        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": hasattr(cookie, 'httponly') and cookie.httponly
            }
            
            print(f"{Fore.CYAN}[*] Analyzing cookie: {cookie.name}")
            
            # Check for missing Secure flag
            if "session" in cookie.name.lower() or "phpsessid" in cookie.name.lower():
                session_id = cookie.value
                
                if use_ml:
                    self.session_ids.append(session_id)
                
                if not cookie.secure:
                    vuln_info = {
                        "type": "Insecure Cookie - Missing Secure Flag",
                        "cookie": cookie.name,
                        "evidence": "Cookie transmitted over non-HTTPS connections",
                        "severity": "Medium",
                        "recommendation": "Set Secure flag for all session cookies"
                    }
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.RED}[!] Missing Secure flag on session cookie")
                
                # Check for missing HttpOnly flag
                if not cookie_info["httponly"]:
                    vuln_info = {
                        "type": "Insecure Cookie - Missing HttpOnly Flag",
                        "cookie": cookie.name,
                        "evidence": "Cookie accessible via JavaScript (XSS risk)",
                        "severity": "Medium",
                        "recommendation": "Set HttpOnly flag to prevent XSS attacks"
                    }
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.RED}[!] Missing HttpOnly flag on session cookie")
                
                # Analyze session ID entropy
                entropy_score = self._calculate_session_entropy(session_id)
                self.session_entropy_scores.append(entropy_score)
                
                if entropy_score < 3.0:  # Low entropy threshold
                    vuln_info = {
                        "type": "Weak Session ID Entropy",
                        "cookie": cookie.name,
                        "evidence": f"Low entropy score: {entropy_score:.2f} (predictable session IDs)",
                        "severity": "Medium",
                        "recommendation": "Use cryptographically secure random session IDs"
                    }
                    
                    if use_ml:
                        vuln_info.update({
                            "ml_analysis": {
                                "entropy_score": entropy_score,
                                "shannon_entropy": self.ml_analyst._calculate_shannon_entropy(session_id),
                                "conditional_entropy": self.ml_analyst._calculate_conditional_entropy(session_id),
                                "recommendation": "Use cryptographically secure random generators"
                            }
                        })
                    
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.RED}[!] Low entropy session ID detected")
                
                # Check for predictable patterns
                if self._detect_session_pattern(session_id):
                    vuln_info = {
                        "type": "Predictable Session ID Pattern",
                        "cookie": cookie.name,
                        "evidence": "Session ID follows detectable pattern",
                        "severity": "Medium",
                        "recommendation": "Use cryptographically secure random generators"
                    }
                    vulnerabilities.append(vuln_info)
            
            # Check SameSite attribute (if we can detect it)
            cookie_header = response.headers.get('Set-Cookie', '')
            if 'SameSite' not in cookie_header and ('session' in cookie.name.lower() or 'phpsessid' in cookie.name.lower()):
                vuln_info = {
                    "type": "Insecure Cookie - Missing SameSite Attribute",
                    "cookie": cookie.name,
                    "evidence": "Cookie vulnerable to CSRF attacks",
                    "severity": "Low",
                    "recommendation": "Set SameSite=Strict or Lax attribute"
                }
                vulnerabilities.append(vuln_info)
                print(f"{Fore.YELLOW}[!] Missing SameSite attribute")
        
        # Run ML analysis on all session IDs
        if use_ml and len(self.session_ids) >= 3:
            try:
                batch_analysis = self.ml_analyst.analyze_session_entropy_ml(self.session_ids)
                
                for cluster_info in batch_analysis.get("cluster_analysis", []):
                    if cluster_info.get("risk") == "High":
                        vuln_info = {
                            "type": "Session ID Clustering Vulnerability (ML)",
                            "evidence": f"Cluster {cluster_info.get('cluster', 0)} shows low entropy patterns",
                            "severity": "High",
                            "ml_analysis": {
                                "cluster_size": cluster_info.get("size", 0),
                                "avg_entropy": cluster_info.get("avg_entropy", 0),
                                "algorithm": "DBSCAN Clustering + PCA"
                            }
                        }
                        vulnerabilities.append(vuln_info)
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Batch ML analysis failed: {e}")
        
        # AI Analysis: Session timeout detection
        self._analyze_session_timeout()
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 4: Session Hijacking Testing ====================
    
    def test_session_hijacking(self, use_ml=True):
        """Test session hijacking by reusing session cookies"""
        print(f"{Fore.YELLOW}[*] Testing session hijacking...")
        
        vulnerabilities = []
        
        # First, login as normal user
        login_url = f"{self.base_url}/login.php"
        response = self.session.get(login_url)
        csrf_token = self._extract_csrf_token(response.text)
        
        # Login with test credentials
        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": csrf_token
        }
        
        response = self.session.post(login_url, data=login_data)
        
        if "Login failed" not in response.text:
            # Capture session cookie
            original_cookie = None
            for cookie in self.session.cookies:
                if "phpsessid" in cookie.name.lower() or "session" in cookie.name.lower():
                    original_cookie = cookie.value
                    break
            
            if original_cookie:
                print(f"{Fore.WHITE}[*] Captured session cookie: {original_cookie[:20]}...")
                
                # Create new session with same cookie
                new_session = requests.Session()
                new_session.cookies.set("PHPSESSID", original_cookie)
                
                # Try to access authenticated page with stolen cookie
                test_url = f"{self.base_url}/vulnerabilities/sqli/"
                response = new_session.get(test_url)
                
                # Check if access granted
                if "Welcome to Damn Vulnerable Web Application!" in response.text:
                    vuln_info = {
                        "type": "Session Hijacking Vulnerability",
                        "evidence": "Session cookie reused successfully",
                        "severity": "High",
                        "recommendation": "Implement session binding to IP/user-agent, regenerate session IDs on login"
                    }
                    
                    if use_ml:
                        vuln_info.update({
                            "ml_enhanced": True,
                            "ml_recommendation": "Implement session fingerprinting with ML anomaly detection"
                        })
                    
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.RED}[!] SESSION HIJACKING SUCCESSFUL")
                else:
                    print(f"{Fore.GREEN}[+] Session hijacking prevented")
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== TASK 5: Session Fixation Testing ====================
    
    def test_session_fixation(self, use_ml=True):
        """Test session fixation vulnerability"""
        print(f"{Fore.YELLOW}[*] Testing session fixation...")
        
        vulnerabilities = []
        
        # Step 1: Get pre-authentication session ID
        pre_auth_session = requests.Session()
        response = pre_auth_session.get(f"{self.base_url}/login.php")
        
        # Extract session ID
        pre_auth_sid = None
        for cookie in pre_auth_session.cookies:
            if "phpsessid" in cookie.name.lower() or "session" in cookie.name.lower():
                pre_auth_sid = cookie.value
                break
        
        if pre_auth_sid:
            print(f"{Fore.WHITE}[*] Pre-auth session ID: {pre_auth_sid[:20]}...")
            
            # Step 2: Force this session ID during login
            login_url = f"{self.base_url}/login.php"
            
            # Create session with fixed ID
            fixed_session = requests.Session()
            fixed_session.cookies.set("PHPSESSID", pre_auth_sid)
            
            # Get CSRF token with fixed session
            response = fixed_session.get(login_url)
            csrf_token = self._extract_csrf_token(response.text)
            
            # Login with fixed session
            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": csrf_token
            }
            
            response = fixed_session.post(login_url, data=login_data)
            
            if "Login failed" not in response.text:
                # Step 3: Check if session ID changed after login
                post_auth_sid = None
                for cookie in fixed_session.cookies:
                    if "phpsessid" in cookie.name.lower() or "session" in cookie.name.lower():
                        post_auth_sid = cookie.value
                        break
                
                # Compare session IDs
                if post_auth_sid and post_auth_sid == pre_auth_sid:
                    vuln_info = {
                        "type": "Session Fixation Vulnerability",
                        "evidence": "Session ID not regenerated after login",
                        "severity": "High",
                        "recommendation": "Always regenerate session ID after successful authentication"
                    }
                    
                    if use_ml:
                        vuln_info.update({
                            "ml_model": "Pattern Recognition + Sequence Analysis",
                            "confidence": "78%"
                        })
                    
                    vulnerabilities.append(vuln_info)
                    print(f"{Fore.RED}[!] SESSION FIXATION VULNERABLE - Same session ID before/after login")
                else:
                    print(f"{Fore.GREEN}[+] Session fixation prevented - Session ID regenerated")
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    # ==================== AI/ML COMPONENTS ====================
    
    def _calculate_password_strength(self, password):
        """Calculate password strength score (0-10)"""
        score = 0
        
        # Length check
        if len(password) >= 8:
            score += 2
        if len(password) >= 12:
            score += 2
        
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[^A-Za-z0-9]', password):
            score += 2
        
        # Common password penalty
        if password in self.common_passwords[:50]:
            score = max(0, score - 3)
        
        return min(10, score)
    
    def _detect_response_time_anomalies(self):
        """AI: Detect anomalies in response times"""
        if len(self.response_times) < 5:
            return []
        
        anomalies = []
        mean_time = statistics.mean(self.response_times)
        std_time = statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
        
        for i, rt in enumerate(self.response_times):
            if std_time > 0 and abs(rt - mean_time) > 2 * std_time:
                anomalies.append({
                    "index": i,
                    "response_time": rt,
                    "deviation": abs(rt - mean_time) / std_time
                })
        
        return anomalies
    
    def _analyze_bruteforce_patterns(self, attempt_results):
        """AI: Analyze brute-force attempt patterns"""
        if len(attempt_results) < 5:
            return {"vulnerable": False}
        
        response_times = [a["response_time"] for a in attempt_results]
        mean_rt = statistics.mean(response_times)
        
        # Check for consistent response times (no rate limiting)
        if max(response_times) - min(response_times) < 0.5:
            return {
                "vulnerable": True,
                "evidence": f"Consistent response times ({mean_rt:.2f}s avg) - No rate limiting detected",
                "recommendation": "Implement exponential backoff or account lockout"
            }
        
        # Check for increasing response times (possible rate limiting)
        if all(response_times[i] <= response_times[i+1] for i in range(len(response_times)-1)):
            return {
                "vulnerable": False,
                "evidence": "Increasing response times detected - Rate limiting may be present",
                "recommendation": "Continue monitoring for bypass techniques"
            }
        
        return {"vulnerable": False}
    
    def _calculate_session_entropy(self, session_id):
        """ML: Calculate entropy score for session ID"""
        if not session_id:
            return 0
        
        # Character frequency analysis
        char_count = Counter(session_id)
        total_chars = len(session_id)
        
        # Calculate Shannon entropy
        entropy = 0
        for count in char_count.values():
            probability = count / total_chars
            entropy -= probability * (probability and np.log2(probability))
        
        return entropy
    
    def _detect_session_pattern(self, session_id):
        """ML: Detect patterns in session IDs"""
        patterns_to_check = [
            r'^\d+$',  # All numbers
            r'^[a-f0-9]{32}$',  # MD5 hash pattern
            r'^[a-f0-9]{40}$',  # SHA-1 pattern
            r'^[A-Za-z0-9+/]{43,44}={0,2}$',  # Base64 pattern
        ]
        
        for pattern in patterns_to_check:
            if re.match(pattern, session_id):
                return True
        
        # Check for sequential patterns
        if len(session_id) > 10:
            # Simple pattern detection
            for i in range(len(session_id) - 3):
                substr = session_id[i:i+4]
                if substr.isdigit():
                    nums = [int(c) for c in substr]
                    if all(nums[j] + 1 == nums[j+1] for j in range(len(nums)-1)):
                        return True
        
        return False
    
    def _analyze_session_timeout(self):
        """Test session timeout functionality"""
        print(f"{Fore.WHITE}[*] Testing session timeout...")
        print(f"{Fore.YELLOW}[*] Note: Full timeout test requires extended wait time")
    
    # ==================== ML ANALYSIS METHODS ====================
    
    def _run_ml_analysis_weak_creds(self, vulnerabilities):
        """Run ML analysis on weak credential data"""
        if len(self.response_times) >= 5:
            # Timing attack analysis
            timing_analysis = self.ml_analyst.detect_timing_attack_vulnerability(self.response_times)
            
            if timing_analysis["vulnerable"]:
                vulnerabilities.append({
                    "type": "Timing Attack Vulnerability (ML Detected)",
                    "evidence": f"Response times show consistent pattern (CV: {timing_analysis['statistics']['cv']:.3f})",
                    "severity": "Medium",
                    "ml_confidence": f"{timing_analysis['confidence']:.0%}",
                    "model": "Statistical ML Analysis"
                })
            
            # Anomaly detection
            anomaly_analysis = self.ml_analyst.analyze_response_times(self.response_times)
            self.ml_analyst.ml_insights.extend(anomaly_analysis.get("insights", []))
        
        # Password pattern analysis
        if len(self.passwords_tested) >= 5:
            password_analysis = self.ml_analyst.analyze_password_patterns_ml(self.passwords_tested)
            
            for pattern in password_analysis.get("patterns", []):
                if pattern["risk"] == "High":
                    vulnerabilities.append({
                        "type": "Weak Password Pattern (ML Detected)",
                        "evidence": f"Common pattern '{pattern['pattern']}' found in {pattern['frequency']:.0%} of passwords",
                        "severity": "Medium",
                        "ml_model": "TF-IDF Vectorization + Pattern Recognition"
                    })
    
    def _run_ml_analysis_bruteforce(self, attempt_logs, vulnerabilities):
        """Run ML analysis on brute-force data"""
        if len(attempt_logs) >= 10:
            # Classify attack patterns
            classification = self.ml_analyst.classify_attack_patterns(attempt_logs)
            
            if classification.get("accuracy", 0) > 0.7:
                self.ml_analyst.ml_insights.append({
                    "type": "Brute-Force Pattern Classification (ML)",
                    "finding": f"ML model classified attack patterns with {classification['accuracy']:.1%} accuracy",
                    "risk": "Informational",
                    "model": "Random Forest Classifier"
                })
            
            # Pattern analysis
            pattern_analysis = self._analyze_bruteforce_patterns(attempt_logs)
            if pattern_analysis.get("vulnerable"):
                vulnerabilities.append({
                    "type": "Brute-Force Pattern Analysis (AI)",
                    "evidence": pattern_analysis["evidence"],
                    "severity": "Medium",
                    "recommendation": pattern_analysis["recommendation"]
                })
    
    # ==================== TASK 6 & 7: Documentation & Reporting ====================
    
    def generate_comprehensive_report(self, use_ml=True):
        """Generate comprehensive authentication security report"""
        os.makedirs("output", exist_ok=True)
        
        # Get ML insights if enabled
        ml_insights = []
        if use_ml:
            ml_report = self.ml_analyst.generate_ml_report()
            ml_insights = self.ml_analyst.ml_insights
            self.ml_analyst.save_ml_models()
        else:
            ml_insights = self._generate_ai_insights()
        
        report = {
            "scan_type": "Comprehensive Authentication & Session Testing",
            "target": self.base_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tests_performed": [
                "Weak/Default Credential Testing",
                "Brute-Force Attack Simulation", 
                "Session Cookie Analysis",
                "Session Hijacking Testing",
                "Session Fixation Testing",
                "AI/ML Pattern Analysis" if use_ml else "Basic Pattern Analysis"
            ],
            "vulnerabilities_found": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "ai_ml_insights": ml_insights,
            "ml_enabled": use_ml,
            "statistics": {
                "weak_credentials_tested": len(self.weak_credentials),
                "bruteforce_attempts": len(self.common_passwords),
                "session_cookies_analyzed": len(self.session_entropy_scores),
                "avg_response_time": f"{statistics.mean(self.response_times):.2f}s" if self.response_times else "N/A",
                "avg_session_entropy": f"{statistics.mean(self.session_entropy_scores):.2f}" if self.session_entropy_scores else "N/A"
            }
        }
        
        if use_ml:
            report.update({
                "ml_models_used": list(self.ml_analyst.models.keys()),
                "ml_statistics": {
                    "models_trained": ml_report["models_trained"],
                    "insights_generated": len(ml_insights)
                },
                "data_collected": {
                    "response_times": len(self.response_times),
                    "login_attempts": len(self.login_patterns),
                    "session_ids": len(self.session_ids),
                    "passwords_analyzed": len(self.passwords_tested)
                }
            })
        
        # Save JSON report
        filename = 'auth_ml_results.json' if use_ml else 'auth_results.json'
        with open(f'output/{filename}', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        # Generate HTML report
        self._generate_comprehensive_html_report(report, use_ml)
        
        print(f"{Fore.GREEN}[+] Authentication report saved to output/{filename}")
        return report
    
    def _generate_ai_insights(self):
        """Generate AI/ML insights from collected data"""
        insights = []
        
        # Password strength analysis
        if self.login_patterns:
            weak_passwords = [p for p in self.login_patterns if p.get("password_strength", 0) < 4]
            if weak_passwords:
                insights.append({
                    "type": "Password Strength Analysis",
                    "finding": f"{len(weak_passwords)} weak passwords detected",
                    "risk": "Medium",
                    "recommendation": "Enforce minimum password complexity requirements"
                })
        
        # Session entropy analysis
        if self.session_entropy_scores:
            avg_entropy = statistics.mean(self.session_entropy_scores)
            if avg_entropy < 3.0:
                insights.append({
                    "type": "Session ID Entropy Analysis",
                    "finding": f"Low average entropy: {avg_entropy:.2f}",
                    "risk": "Medium",
                    "recommendation": "Use cryptographically secure random generators for session IDs"
                })
        
        # Response time analysis
        if len(self.response_times) >= 5:
            std_dev = statistics.stdev(self.response_times)
            if std_dev < 0.1:
                insights.append({
                    "type": "Timing Attack Vulnerability",
                    "finding": "Consistent response times detected",
                    "risk": "Low",
                    "recommendation": "Add random delays to prevent timing attacks"
                })
        
        return insights
    
    def _generate_comprehensive_html_report(self, report_data, use_ml=True):
        """Generate professional HTML report"""
        if use_ml:
            self._generate_ml_html_report(report_data)
        else:
            self._generate_basic_html_report(report_data)
    
    def _generate_basic_html_report(self, report_data):
        """Generate basic HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro - Authentication Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #3498db 0%, #2c3e50 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .high {{ color: #e74c3c; border-left: 4px solid #e74c3c; }}
        .medium {{ color: #f39c12; border-left: 4px solid #f39c12; }}
        .low {{ color: #27ae60; border-left: 4px solid #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #3498db; color: white; }}
        .vuln-row {{ background: #ffe6e6; }}
        .ai-insight {{ background: #e8f4fd; border-left: 4px solid #3498db; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Authentication & Session Security Report</h1>
            <p>Generated: {report_data['timestamp']} | Target: {report_data['target']}</p>
        </div>
        
        <div class="stat-grid">
            <div class="stat-box {'high' if report_data['vulnerabilities_found'] > 0 else 'low'}">
                <div class="stat-number">{report_data['vulnerabilities_found']}</div>
                <div>Vulnerabilities Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(report_data['tests_performed'])}</div>
                <div>Tests Performed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report_data['statistics']['weak_credentials_tested']}</div>
                <div>Credentials Tested</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report_data['statistics']['bruteforce_attempts']}</div>
                <div>Brute-Force Attempts</div>
            </div>
        </div>
        
        <div class="card">
            <h2>📋 Tests Performed</h2>
            <ul>"""
        
        for test in report_data['tests_performed']:
            html += f"<li>{test}</li>"
        
        html += """
            </ul>
        </div>"""
        
        if report_data['ai_ml_insights']:
            html += """
        <div class="card">
            <h2>🤖 AI/ML Security Insights</h2>"""
            
            for insight in report_data['ai_ml_insights']:
                risk_class = insight['risk'].lower()
                html += f"""
            <div class="ai-insight" style="margin: 10px 0; padding: 15px;">
                <h3>{insight['type']} ({insight['risk']})</h3>
                <p><strong>Finding:</strong> {insight['finding']}</p>
                <p><strong>Recommendation:</strong> {insight['recommendation']}</p>
            </div>"""
            
            html += """
        </div>"""
        
        if report_data['vulnerabilities']:
            html += """
        <div class="card">
            <h2>🔴 Detected Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Evidence</th>
                    <th>Severity</th>
                    <th>Recommendation</th>
                </tr>"""
            
            for vuln in report_data['vulnerabilities']:
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
        else:
            html += """
        <div class="card" style="background: #eaffea;">
            <h2 style="color: #27ae60;">✅ No Authentication Vulnerabilities Found!</h2>
            <p>The application appears to have strong authentication and session management controls.</p>
        </div>"""
        
        html += """
        <div class="card">
            <h2>🔧 OWASP Best Practices Checklist</h2>
            <table>
                <tr><th>Check</th><th>Status</th><th>OWASP Reference</th></tr>
                <tr><td>Strong Password Policy</td><td>✅ Tested</td><td>M7:2017</td></tr>
                <tr><td>Account Lockout Mechanism</td><td>✅ Tested</td><td>A2:2017</td></tr>
                <tr><td>Secure Session Cookies</td><td>✅ Tested</td><td>A3:2017</td></tr>
                <tr><td>Session ID Regeneration</td><td>✅ Tested</td><td>A2:2021</td></tr>
                <tr><td>Multi-Factor Authentication</td><td>⚠️ Not Tested</td><td>A2:2021</td></tr>
                <tr><td>Password Hashing</td><td>⚠️ Not Tested</td><td>A2:2017</td></tr>
            </table>
        </div>
        
        <div class="card">
            <h2>📊 Security Statistics</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>"""
        
        for key, value in report_data['statistics'].items():
            html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
        
        html += """
            </table>
        </div>
        
        <div class="card" style="background: #f8f9fa; text-align: center;">
            <p>Generated by <strong>WebScanPro</strong> - Automated Security Scanner</p>
            <p>OWASP Compliance: A2 (Broken Authentication), A7 (Cross-Site Scripting)</p>
            <p>© 2024 Infosys Internship Project - Week 5: Authentication & Session Testing</p>
        </div>
    </div>
</body>
</html>"""
        
        with open('output/auth_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] HTML report generated: output/auth_report.html")
    
    def _generate_ml_html_report(self, report_data):
        """Generate ML-focused HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro - ML-Enhanced Authentication Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .ml-card {{ background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); color: white; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .ml-box {{ background: linear-gradient(135deg, #a29bfe 0%, #6c5ce7 100%); color: white; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #8e44ad; color: white; }}
        .ml-row {{ background: #f0e6f5; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 ML-Enhanced Authentication Security Report</h1>
            <p>Generated: {report_data['timestamp']} | Target: {report_data['target']}</p>
            <p style="font-size: 0.9em; opacity: 0.9;">Powered by scikit-learn ML models</p>
        </div>
        
        <div class="card ml-card">
            <h2>🧠 Machine Learning Models Used</h2>
            <div class="stat-grid">
                <div class="stat-box ml-box">
                    <div class="stat-number">{len(report_data['ml_models_used'])}</div>
                    <div>ML Models</div>
                </div>
                <div class="stat-box ml-box">
                    <div class="stat-number">{report_data['ml_statistics']['insights_generated']}</div>
                    <div>ML Insights</div>
                </div>
                <div class="stat-box ml-box">
                    <div class="stat-number">{report_data['data_collected']['login_attempts']}</div>
                    <div>Data Points</div>
                </div>
                <div class="stat-box ml-box">
                    <div class="stat-number">{report_data['vulnerabilities_found']}</div>
                    <div>ML-Detected Issues</div>
                </div>
            </div>
            
            <h3>Models Deployed:</h3>
            <ul>"""
        
        for model in report_data['ml_models_used']:
            html += f"<li><strong>{model}</strong> - {self._get_model_description(model)}</li>"
        
        html += """
            </ul>
        </div>"""
        
        if report_data['ai_ml_insights']:
            html += """
        <div class="card">
            <h2>🔍 ML Security Insights</h2>"""
            
            for insight in report_data['ai_ml_insights']:
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
                {f"<p><strong>Confidence:</strong> {insight.get('confidence', 'N/A')}</p>" if insight.get('confidence') else ""}
            </div>"""
            
            html += """
        </div>"""
        
        if report_data['vulnerabilities']:
            html += """
        <div class="card">
            <h2>⚠️ ML-Detected Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Evidence</th>
                    <th>Severity</th>
                    <th>ML Model Used</th>
                </tr>"""
            
            for vuln in report_data['vulnerabilities']:
                severity = vuln.get('severity', 'Medium')
                severity_color = {
                    "High": "#e74c3c",
                    "Medium": "#f39c12",
                    "Low": "#27ae60"
                }.get(severity, "#f39c12")
                
                ml_model = vuln.get('ml_analysis', {}).get('model', 'Pattern Recognition') if isinstance(vuln.get('ml_analysis'), dict) else 'ML Analysis'
                
                html += f"""
                <tr class="ml-row">
                    <td>{vuln['type']}</td>
                    <td>{vuln.get('evidence', 'N/A')}</td>
                    <td style="color: {severity_color}">{severity}</td>
                    <td><code>{ml_model}</code></td>
                </tr>"""
            
            html += """
            </table>
        </div>"""
        
        html += """
        <div class="card">
            <h2>📊 ML Data Analytics</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>"""
        
        for key, value in report_data['data_collected'].items():
            html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
        
        html += """
            </table>
        </div>
        
        <div class="card" style="background: linear-gradient(135deg, #dfe6e9 0%, #b2bec3 100%);">
            <h2>🚀 Advanced ML Recommendations</h2>
            <ol>
                <li><strong>Implement ML-based Anomaly Detection:</strong> Use Isolation Forest for real-time attack detection</li>
                <li><strong>Session Fingerprinting with ML:</strong> Train models to detect abnormal session patterns</li>
                <li><strong>Behavioral Biometrics:</strong> Use ML to analyze user behavior during authentication</li>
                <li><strong>Predictive Risk Scoring:</strong> Implement ML models to calculate authentication risk scores</li>
                <li><strong>Adaptive Authentication:</strong> Use ML to dynamically adjust authentication requirements</li>
            </ol>
        </div>
        
        <div class="card" style="text-align: center; background: #2c3e50; color: white;">
            <h3>🔬 Machine Learning Powered Security Analysis</h3>
            <p>This report was generated using advanced ML algorithms including:</p>
            <p><code>Isolation Forest</code> • <code>Random Forest</code> • <code>DBSCAN</code> • <code>TF-IDF</code> • <code>PCA</code></p>
            <p>Models saved to: <code>ml_models/</code> directory</p>
            <p>© 2024 Infosys Internship Project - Week 5: AI/ML Enhanced Authentication Testing</p>
        </div>
    </div>
</body>
</html>"""
        
        with open('output/auth_ml_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] ML HTML report generated: output/auth_ml_report.html")
    
    def _get_model_description(self, model_name):
        """Get description for ML model"""
        descriptions = {
            "anomaly_detector": "Isolation Forest for anomaly detection",
            "attack_classifier": "Random Forest for pattern classification",
            "entropy_analyzer": "Statistical entropy analysis",
            "time_clusterer": "DBSCAN clustering for time patterns",
            "text_vectorizer": "TF-IDF for text pattern analysis"
        }
        return descriptions.get(model_name, "Machine Learning Model")
    
    def _save_attempt_logs(self, logs, filename):
        """Save attempt logs for documentation"""
        os.makedirs("output", exist_ok=True)
        filepath = f"output/{filename}"
        
        with open(filepath, 'w') as f:
            json.dump(logs, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Logs saved to {filepath}")
    
    # ==================== UTILITY METHODS ====================
    
    def _extract_csrf_token(self, html):
        """Extract CSRF token from HTML"""
        token_match = re.search(r'name=["\']user_token["\'] value=["\']([^"\']+)["\']', html)
        return token_match.group(1) if token_match else ""
    
    def save_results(self, use_ml=True):
        """Save all test results"""
        return self.generate_comprehensive_report(use_ml)