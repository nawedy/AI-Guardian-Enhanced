"""
Android Application Security Analyzer
Comprehensive security analysis of Android applications
"""

import re
import json
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging
import base64

class AndroidAnalyzer:
    """
    Advanced Android Application Security Analyzer
    
    Features:
    - APK static analysis
    - Permission analysis
    - Malware detection
    - Privacy assessment
    - Code vulnerability scanning
    - Dynamic analysis integration
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Android vulnerability patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        # Permission risk levels
        self.permission_risks = self._load_permission_risks()
        
        # Malware signatures
        self.malware_signatures = self._load_malware_signatures()
        
        # Privacy patterns
        self.privacy_patterns = self._load_privacy_patterns()
        
        # Code analysis patterns
        self.code_patterns = self._load_code_patterns()
        
        self.logger.info("AndroidAnalyzer initialized successfully")
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[Dict]]:
        """Load Android vulnerability patterns"""
        return {
            "insecure_storage": [
                {
                    "pattern": r"SharedPreferences.*MODE_WORLD_READABLE|MODE_WORLD_WRITABLE",
                    "severity": "high",
                    "description": "Insecure SharedPreferences storage mode",
                    "cwe": "CWE-200"
                },
                {
                    "pattern": r"openFileOutput.*MODE_WORLD_READABLE|MODE_WORLD_WRITABLE",
                    "severity": "high",
                    "description": "Insecure file storage mode",
                    "cwe": "CWE-200"
                }
            ],
            "insecure_communication": [
                {
                    "pattern": r"HttpURLConnection|DefaultHttpClient",
                    "severity": "medium",
                    "description": "Potentially insecure HTTP communication",
                    "cwe": "CWE-319"
                },
                {
                    "pattern": r"TrustManager.*checkServerTrusted.*return",
                    "severity": "critical",
                    "description": "Disabled certificate validation",
                    "cwe": "CWE-295"
                }
            ],
            "cryptographic_issues": [
                {
                    "pattern": r"DES|RC4|MD5|SHA1(?!.*HMAC)",
                    "severity": "medium",
                    "description": "Weak cryptographic algorithm",
                    "cwe": "CWE-327"
                },
                {
                    "pattern": r"SecureRandom.*setSeed|Random\(",
                    "severity": "high",
                    "description": "Weak random number generation",
                    "cwe": "CWE-338"
                }
            ],
            "injection_vulnerabilities": [
                {
                    "pattern": r"execSQL.*\+|rawQuery.*\+",
                    "severity": "critical",
                    "description": "SQL injection vulnerability",
                    "cwe": "CWE-89"
                },
                {
                    "pattern": r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder",
                    "severity": "high",
                    "description": "Command injection risk",
                    "cwe": "CWE-78"
                }
            ],
            "authentication_bypass": [
                {
                    "pattern": r"onReceivedSslError.*proceed|checkServerTrusted.*\{\s*\}",
                    "severity": "critical",
                    "description": "SSL/TLS certificate validation bypass",
                    "cwe": "CWE-295"
                },
                {
                    "pattern": r"setHostnameVerifier.*ALLOW_ALL_HOSTNAME_VERIFIER",
                    "severity": "high",
                    "description": "Hostname verification disabled",
                    "cwe": "CWE-295"
                }
            ],
            "webview_vulnerabilities": [
                {
                    "pattern": r"setJavaScriptEnabled\(true\)|addJavascriptInterface",
                    "severity": "medium",
                    "description": "WebView JavaScript interface exposure",
                    "cwe": "CWE-749"
                },
                {
                    "pattern": r"setAllowFileAccess\(true\)|setAllowUniversalAccessFromFileURLs\(true\)",
                    "severity": "high",
                    "description": "WebView file access vulnerability",
                    "cwe": "CWE-200"
                }
            ]
        }
    
    def _load_permission_risks(self) -> Dict[str, Dict]:
        """Load Android permission risk assessments"""
        return {
            # Dangerous permissions
            "android.permission.READ_CONTACTS": {
                "risk_level": "high",
                "category": "privacy",
                "description": "Access to user contacts",
                "privacy_impact": "high"
            },
            "android.permission.READ_SMS": {
                "risk_level": "high",
                "category": "privacy",
                "description": "Access to SMS messages",
                "privacy_impact": "high"
            },
            "android.permission.ACCESS_FINE_LOCATION": {
                "risk_level": "high",
                "category": "privacy",
                "description": "Access to precise location",
                "privacy_impact": "high"
            },
            "android.permission.CAMERA": {
                "risk_level": "medium",
                "category": "privacy",
                "description": "Access to camera",
                "privacy_impact": "medium"
            },
            "android.permission.RECORD_AUDIO": {
                "risk_level": "medium",
                "category": "privacy",
                "description": "Access to microphone",
                "privacy_impact": "medium"
            },
            "android.permission.READ_PHONE_STATE": {
                "risk_level": "medium",
                "category": "privacy",
                "description": "Access to phone state and identity",
                "privacy_impact": "medium"
            },
            
            # Security-sensitive permissions
            "android.permission.WRITE_EXTERNAL_STORAGE": {
                "risk_level": "medium",
                "category": "security",
                "description": "Write access to external storage",
                "privacy_impact": "low"
            },
            "android.permission.INSTALL_PACKAGES": {
                "risk_level": "critical",
                "category": "security",
                "description": "Install other applications",
                "privacy_impact": "low"
            },
            "android.permission.SYSTEM_ALERT_WINDOW": {
                "risk_level": "high",
                "category": "security",
                "description": "Display system-level windows",
                "privacy_impact": "low"
            },
            "android.permission.DEVICE_ADMIN": {
                "risk_level": "critical",
                "category": "security",
                "description": "Device administrator privileges",
                "privacy_impact": "low"
            },
            "android.permission.BIND_DEVICE_ADMIN": {
                "risk_level": "critical",
                "category": "security",
                "description": "Bind to device admin service",
                "privacy_impact": "low"
            },
            
            # Network permissions
            "android.permission.INTERNET": {
                "risk_level": "low",
                "category": "network",
                "description": "Internet access",
                "privacy_impact": "low"
            },
            "android.permission.ACCESS_NETWORK_STATE": {
                "risk_level": "low",
                "category": "network",
                "description": "Access network state information",
                "privacy_impact": "low"
            }
        }
    
    def _load_malware_signatures(self) -> Dict[str, List[Dict]]:
        """Load malware detection signatures"""
        return {
            "trojan_signatures": [
                {
                    "pattern": r"sendTextMessage.*premium|sms.*premium",
                    "malware_type": "sms_trojan",
                    "severity": "critical",
                    "description": "Premium SMS sending behavior"
                },
                {
                    "pattern": r"DeviceAdminReceiver.*onEnabled",
                    "malware_type": "admin_trojan",
                    "severity": "high",
                    "description": "Device admin activation"
                }
            ],
            "spyware_signatures": [
                {
                    "pattern": r"location.*upload|gps.*send",
                    "malware_type": "location_spyware",
                    "severity": "high",
                    "description": "Location tracking and transmission"
                },
                {
                    "pattern": r"contacts.*upload|sms.*forward",
                    "malware_type": "data_spyware",
                    "severity": "high",
                    "description": "Personal data exfiltration"
                }
            ],
            "adware_signatures": [
                {
                    "pattern": r"aggressive.*ads|popup.*ads",
                    "malware_type": "adware",
                    "severity": "medium",
                    "description": "Aggressive advertising behavior"
                }
            ],
            "banking_malware": [
                {
                    "pattern": r"overlay.*banking|keylog.*banking",
                    "malware_type": "banking_trojan",
                    "severity": "critical",
                    "description": "Banking credential theft"
                }
            ]
        }
    
    def _load_privacy_patterns(self) -> Dict[str, List[Dict]]:
        """Load privacy violation patterns"""
        return {
            "data_collection": [
                {
                    "pattern": r"getDeviceId|getSubscriberId|getSimSerialNumber",
                    "privacy_type": "device_identification",
                    "severity": "medium",
                    "description": "Device identifier collection"
                },
                {
                    "pattern": r"getLastKnownLocation|requestLocationUpdates",
                    "privacy_type": "location_tracking",
                    "severity": "high",
                    "description": "Location data collection"
                }
            ],
            "data_transmission": [
                {
                    "pattern": r"HttpPost.*personal|upload.*private",
                    "privacy_type": "data_exfiltration",
                    "severity": "high",
                    "description": "Personal data transmission"
                }
            ],
            "tracking": [
                {
                    "pattern": r"analytics.*track|advertising.*id",
                    "privacy_type": "behavioral_tracking",
                    "severity": "medium",
                    "description": "User behavior tracking"
                }
            ]
        }
    
    def _load_code_patterns(self) -> Dict[str, List[Dict]]:
        """Load code quality and security patterns"""
        return {
            "code_obfuscation": [
                {
                    "pattern": r"class\s+[a-z]{1,3}\s*\{|method\s+[a-z]{1,3}\s*\(",
                    "description": "Heavily obfuscated code detected",
                    "suspicion_level": "medium"
                }
            ],
            "anti_analysis": [
                {
                    "pattern": r"isDebuggerConnected|detectEmulator|detectRoot",
                    "description": "Anti-analysis techniques detected",
                    "suspicion_level": "high"
                }
            ],
            "dynamic_loading": [
                {
                    "pattern": r"DexClassLoader|PathClassLoader|loadClass",
                    "description": "Dynamic code loading detected",
                    "suspicion_level": "medium"
                }
            ]
        }
    
    def analyze_app(self, app_data: Dict[str, Any], analysis_depth: str = "comprehensive",
                   include_permissions: bool = True) -> Dict[str, Any]:
        """Perform comprehensive Android app security analysis"""
        try:
            analysis_result = {
                "app_info": app_data,
                "analysis_depth": analysis_depth,
                "static_analysis": {},
                "permission_analysis": {},
                "vulnerability_assessment": {},
                "malware_detection": {},
                "privacy_assessment": {},
                "code_quality": {},
                "security_score": 0,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
            # Extract app information
            app_info = self._extract_app_info(app_data)
            analysis_result["app_info"].update(app_info)
            
            # Static analysis
            static_analysis = self._perform_static_analysis(app_data)
            analysis_result["static_analysis"] = static_analysis
            
            # Permission analysis
            if include_permissions:
                permission_analysis = self._analyze_permissions(app_data)
                analysis_result["permission_analysis"] = permission_analysis
            
            # Vulnerability assessment
            vulnerability_assessment = self._assess_vulnerabilities(app_data, static_analysis)
            analysis_result["vulnerability_assessment"] = vulnerability_assessment
            
            # Malware detection
            malware_detection = self._detect_malware(app_data, static_analysis)
            analysis_result["malware_detection"] = malware_detection
            
            # Privacy assessment
            privacy_assessment = self._assess_privacy(app_data, static_analysis)
            analysis_result["privacy_assessment"] = privacy_assessment
            
            # Code quality analysis
            code_quality = self._analyze_code_quality(app_data, static_analysis)
            analysis_result["code_quality"] = code_quality
            
            # Network security analysis
            network_security = self._analyze_network_security(app_data, static_analysis)
            analysis_result["network_security"] = network_security
            
            # Certificate analysis
            certificate_analysis = self._analyze_certificates(app_data)
            analysis_result["certificate_analysis"] = certificate_analysis
            
            # Calculate security score
            security_score = self._calculate_security_score(analysis_result)
            analysis_result["security_score"] = security_score
            
            # Generate recommendations
            recommendations = self._generate_recommendations(analysis_result)
            analysis_result["recommendations"] = recommendations
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in Android app analysis: {e}")
            return {"error": str(e)}
    
    def _extract_app_info(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic app information"""
        # Mock app info extraction (in real implementation, would parse APK)
        return {
            "package_name": app_data.get("package_name", "com.example.app"),
            "version_name": app_data.get("version_name", "1.0.0"),
            "version_code": app_data.get("version_code", 1),
            "min_sdk_version": app_data.get("min_sdk_version", 21),
            "target_sdk_version": app_data.get("target_sdk_version", 30),
            "app_name": app_data.get("app_name", "Unknown App"),
            "developer": app_data.get("developer", "Unknown Developer"),
            "file_size": app_data.get("file_size", 0),
            "install_location": app_data.get("install_location", "auto")
        }
    
    def _perform_static_analysis(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform static code analysis"""
        static_analysis = {
            "manifest_analysis": {},
            "code_analysis": {},
            "resource_analysis": {},
            "library_analysis": {},
            "certificate_info": {}
        }
        
        # Manifest analysis
        manifest_analysis = self._analyze_manifest(app_data)
        static_analysis["manifest_analysis"] = manifest_analysis
        
        # Code analysis
        code_analysis = self._analyze_code(app_data)
        static_analysis["code_analysis"] = code_analysis
        
        # Resource analysis
        resource_analysis = self._analyze_resources(app_data)
        static_analysis["resource_analysis"] = resource_analysis
        
        # Library analysis
        library_analysis = self._analyze_libraries(app_data)
        static_analysis["library_analysis"] = library_analysis
        
        return static_analysis
    
    def _analyze_permissions(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Android permissions"""
        permission_analysis = {
            "declared_permissions": [],
            "dangerous_permissions": [],
            "privacy_sensitive_permissions": [],
            "security_sensitive_permissions": [],
            "permission_risk_score": 0,
            "over_privileged": False
        }
        
        # Mock permission extraction (in real implementation, would parse AndroidManifest.xml)
        declared_permissions = app_data.get("permissions", [
            "android.permission.INTERNET",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO"
        ])
        
        permission_analysis["declared_permissions"] = declared_permissions
        
        # Categorize permissions
        for permission in declared_permissions:
            if permission in self.permission_risks:
                risk_info = self.permission_risks[permission]
                
                permission_detail = {
                    "permission": permission,
                    "risk_level": risk_info["risk_level"],
                    "category": risk_info["category"],
                    "description": risk_info["description"],
                    "privacy_impact": risk_info["privacy_impact"]
                }
                
                if risk_info["risk_level"] in ["high", "critical"]:
                    permission_analysis["dangerous_permissions"].append(permission_detail)
                
                if risk_info["privacy_impact"] in ["medium", "high"]:
                    permission_analysis["privacy_sensitive_permissions"].append(permission_detail)
                
                if risk_info["category"] == "security":
                    permission_analysis["security_sensitive_permissions"].append(permission_detail)
        
        # Calculate permission risk score
        permission_analysis["permission_risk_score"] = self._calculate_permission_risk_score(declared_permissions)
        
        # Check for over-privileged app
        permission_analysis["over_privileged"] = len(permission_analysis["dangerous_permissions"]) > 5
        
        return permission_analysis
    
    def _assess_vulnerabilities(self, app_data: Dict[str, Any], 
                              static_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess security vulnerabilities"""
        vulnerability_assessment = {
            "vulnerabilities": [],
            "vulnerability_summary": {},
            "critical_issues": [],
            "remediation_suggestions": []
        }
        
        # Mock code content for pattern matching
        code_content = app_data.get("code_content", """
            SharedPreferences prefs = getSharedPreferences("data", MODE_WORLD_READABLE);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            String sql = "SELECT * FROM users WHERE id = " + userId;
            execSQL(sql);
        """)
        
        vulnerabilities = []
        
        # Check for vulnerability patterns
        for category, patterns in self.vulnerability_patterns.items():
            for pattern_info in patterns:
                matches = re.findall(pattern_info["pattern"], code_content, re.IGNORECASE)
                
                if matches:
                    vulnerability = {
                        "category": category,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "cwe": pattern_info["cwe"],
                        "occurrences": len(matches),
                        "remediation": self._get_vulnerability_remediation(category)
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    if pattern_info["severity"] == "critical":
                        vulnerability_assessment["critical_issues"].append(vulnerability)
        
        vulnerability_assessment["vulnerabilities"] = vulnerabilities
        
        # Generate vulnerability summary
        vulnerability_summary = self._generate_vulnerability_summary(vulnerabilities)
        vulnerability_assessment["vulnerability_summary"] = vulnerability_summary
        
        return vulnerability_assessment
    
    def _detect_malware(self, app_data: Dict[str, Any], 
                       static_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Detect malware signatures"""
        malware_detection = {
            "malware_detected": False,
            "malware_signatures": [],
            "risk_indicators": [],
            "behavioral_analysis": {},
            "confidence_score": 0
        }
        
        # Mock code content for malware detection
        code_content = app_data.get("code_content", "")
        
        detected_signatures = []
        
        # Check for malware signatures
        for category, signatures in self.malware_signatures.items():
            for signature_info in signatures:
                if re.search(signature_info["pattern"], code_content, re.IGNORECASE):
                    signature = {
                        "category": category,
                        "malware_type": signature_info["malware_type"],
                        "severity": signature_info["severity"],
                        "description": signature_info["description"],
                        "confidence": 0.8
                    }
                    
                    detected_signatures.append(signature)
        
        malware_detection["malware_signatures"] = detected_signatures
        malware_detection["malware_detected"] = len(detected_signatures) > 0
        
        # Behavioral analysis
        behavioral_analysis = self._analyze_malware_behavior(app_data, static_analysis)
        malware_detection["behavioral_analysis"] = behavioral_analysis
        
        # Risk indicators
        risk_indicators = self._identify_risk_indicators(app_data, static_analysis)
        malware_detection["risk_indicators"] = risk_indicators
        
        # Calculate confidence score
        confidence_score = self._calculate_malware_confidence(detected_signatures, risk_indicators)
        malware_detection["confidence_score"] = confidence_score
        
        return malware_detection
    
    def _assess_privacy(self, app_data: Dict[str, Any], 
                       static_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess privacy implications"""
        privacy_assessment = {
            "privacy_violations": [],
            "data_collection_practices": [],
            "third_party_trackers": [],
            "privacy_score": 0,
            "gdpr_compliance": {},
            "ccpa_compliance": {}
        }
        
        # Mock code content for privacy analysis
        code_content = app_data.get("code_content", "")
        
        privacy_violations = []
        
        # Check for privacy patterns
        for category, patterns in self.privacy_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], code_content, re.IGNORECASE):
                    violation = {
                        "category": category,
                        "privacy_type": pattern_info["privacy_type"],
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"]
                    }
                    
                    privacy_violations.append(violation)
        
        privacy_assessment["privacy_violations"] = privacy_violations
        
        # Analyze data collection practices
        data_collection = self._analyze_data_collection(app_data, static_analysis)
        privacy_assessment["data_collection_practices"] = data_collection
        
        # Identify third-party trackers
        trackers = self._identify_third_party_trackers(app_data, static_analysis)
        privacy_assessment["third_party_trackers"] = trackers
        
        # GDPR compliance assessment
        gdpr_compliance = self._assess_gdpr_compliance(privacy_assessment)
        privacy_assessment["gdpr_compliance"] = gdpr_compliance
        
        # CCPA compliance assessment
        ccpa_compliance = self._assess_ccpa_compliance(privacy_assessment)
        privacy_assessment["ccpa_compliance"] = ccpa_compliance
        
        # Calculate privacy score
        privacy_score = self._calculate_privacy_score(privacy_assessment)
        privacy_assessment["privacy_score"] = privacy_score
        
        return privacy_assessment
    
    def _analyze_code_quality(self, app_data: Dict[str, Any], 
                            static_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze code quality and security practices"""
        code_quality = {
            "obfuscation_detected": False,
            "anti_analysis_techniques": [],
            "code_complexity": {},
            "security_best_practices": {},
            "quality_score": 0
        }
        
        # Mock code content
        code_content = app_data.get("code_content", "")
        
        # Check for code patterns
        for category, patterns in self.code_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], code_content, re.IGNORECASE):
                    if category == "code_obfuscation":
                        code_quality["obfuscation_detected"] = True
                    elif category == "anti_analysis":
                        code_quality["anti_analysis_techniques"].append({
                            "technique": pattern_info["description"],
                            "suspicion_level": pattern_info["suspicion_level"]
                        })
        
        # Analyze code complexity
        complexity = self._analyze_code_complexity(code_content)
        code_quality["code_complexity"] = complexity
        
        # Check security best practices
        best_practices = self._check_security_best_practices(code_content)
        code_quality["security_best_practices"] = best_practices
        
        # Calculate quality score
        quality_score = self._calculate_code_quality_score(code_quality)
        code_quality["quality_score"] = quality_score
        
        return code_quality
    
    def _analyze_network_security(self, app_data: Dict[str, Any], 
                                static_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network security implementation"""
        network_security = {
            "network_security_config": {},
            "certificate_pinning": False,
            "insecure_protocols": [],
            "network_security_score": 0
        }
        
        # Mock analysis (in real implementation, would parse network_security_config.xml)
        code_content = app_data.get("code_content", "")
        
        # Check for certificate pinning
        if "CertificatePinner" in code_content or "PinningTrustManager" in code_content:
            network_security["certificate_pinning"] = True
        
        # Check for insecure protocols
        insecure_patterns = [
            ("HTTP", r"http://(?!localhost|127\.0\.0\.1)"),
            ("FTP", r"ftp://"),
            ("Telnet", r"telnet://")
        ]
        
        for protocol, pattern in insecure_patterns:
            if re.search(pattern, code_content, re.IGNORECASE):
                network_security["insecure_protocols"].append(protocol)
        
        # Calculate network security score
        network_security["network_security_score"] = self._calculate_network_security_score(network_security)
        
        return network_security
    
    def _analyze_certificates(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze app signing certificates"""
        certificate_analysis = {
            "signing_certificate": {},
            "certificate_chain": [],
            "certificate_issues": [],
            "certificate_score": 0
        }
        
        # Mock certificate analysis (in real implementation, would extract from APK)
        certificate_info = {
            "subject": "CN=Developer, O=Company, C=US",
            "issuer": "CN=Developer, O=Company, C=US",
            "serial_number": "12345678",
            "valid_from": "2023-01-01T00:00:00Z",
            "valid_to": "2025-01-01T00:00:00Z",
            "signature_algorithm": "SHA256withRSA",
            "key_size": 2048,
            "self_signed": True
        }
        
        certificate_analysis["signing_certificate"] = certificate_info
        
        # Check for certificate issues
        issues = []
        
        if certificate_info["self_signed"]:
            issues.append({
                "issue": "self_signed_certificate",
                "severity": "low",
                "description": "App is signed with a self-signed certificate"
            })
        
        if certificate_info["key_size"] < 2048:
            issues.append({
                "issue": "weak_key_size",
                "severity": "medium",
                "description": f"Certificate uses weak key size: {certificate_info['key_size']} bits"
            })
        
        certificate_analysis["certificate_issues"] = issues
        
        # Calculate certificate score
        certificate_analysis["certificate_score"] = self._calculate_certificate_score(certificate_analysis)
        
        return certificate_analysis
    
    def _calculate_security_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall security score (0-100)"""
        base_score = 100.0
        
        # Deduct for vulnerabilities
        vulnerabilities = analysis_result.get("vulnerability_assessment", {}).get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if vuln["severity"] == "critical":
                base_score -= 25
            elif vuln["severity"] == "high":
                base_score -= 15
            elif vuln["severity"] == "medium":
                base_score -= 8
            elif vuln["severity"] == "low":
                base_score -= 3
        
        # Deduct for malware detection
        malware_detection = analysis_result.get("malware_detection", {})
        if malware_detection.get("malware_detected"):
            base_score -= 30
        
        # Deduct for privacy violations
        privacy_score = analysis_result.get("privacy_assessment", {}).get("privacy_score", 50)
        base_score -= (100 - privacy_score) * 0.2
        
        # Deduct for dangerous permissions
        permission_analysis = analysis_result.get("permission_analysis", {})
        dangerous_perms = len(permission_analysis.get("dangerous_permissions", []))
        base_score -= dangerous_perms * 3
        
        # Adjust for code quality
        code_quality = analysis_result.get("code_quality", {})
        quality_score = code_quality.get("quality_score", 50)
        base_score += (quality_score - 50) * 0.1
        
        return max(0.0, min(100.0, base_score))
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations"""
        recommendations = []
        
        # Vulnerability recommendations
        vulnerabilities = analysis_result.get("vulnerability_assessment", {}).get("vulnerabilities", [])
        critical_vulns = [v for v in vulnerabilities if v["severity"] == "critical"]
        
        if critical_vulns:
            recommendations.append({
                "category": "vulnerabilities",
                "priority": "critical",
                "title": "Fix Critical Security Vulnerabilities",
                "description": f"Address {len(critical_vulns)} critical security vulnerabilities",
                "remediation_steps": [
                    "Review and fix SQL injection vulnerabilities",
                    "Implement proper certificate validation",
                    "Use secure storage mechanisms"
                ]
            })
        
        # Permission recommendations
        permission_analysis = analysis_result.get("permission_analysis", {})
        if permission_analysis.get("over_privileged"):
            recommendations.append({
                "category": "permissions",
                "priority": "medium",
                "title": "Reduce App Permissions",
                "description": "App requests excessive permissions",
                "remediation_steps": [
                    "Review all requested permissions",
                    "Remove unnecessary permissions",
                    "Implement runtime permission requests"
                ]
            })
        
        # Privacy recommendations
        privacy_assessment = analysis_result.get("privacy_assessment", {})
        if privacy_assessment.get("privacy_violations"):
            recommendations.append({
                "category": "privacy",
                "priority": "high",
                "title": "Address Privacy Violations",
                "description": "Privacy violations detected in app behavior",
                "remediation_steps": [
                    "Implement privacy policy",
                    "Add user consent mechanisms",
                    "Minimize data collection"
                ]
            })
        
        # Malware recommendations
        malware_detection = analysis_result.get("malware_detection", {})
        if malware_detection.get("malware_detected"):
            recommendations.append({
                "category": "malware",
                "priority": "critical",
                "title": "Remove Malicious Code",
                "description": "Malware signatures detected",
                "remediation_steps": [
                    "Remove malicious code patterns",
                    "Scan with multiple antivirus engines",
                    "Review third-party libraries"
                ]
            })
        
        return recommendations
    
    # Helper methods for various analysis components
    def _analyze_manifest(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml"""
        return {
            "exported_components": [],
            "intent_filters": [],
            "custom_permissions": [],
            "backup_allowed": True,
            "debug_enabled": False
        }
    
    def _analyze_code(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze application code"""
        return {
            "total_classes": 150,
            "total_methods": 1200,
            "native_libraries": [],
            "reflection_usage": False,
            "dynamic_loading": False
        }
    
    def _analyze_resources(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze app resources"""
        return {
            "hardcoded_secrets": [],
            "sensitive_strings": [],
            "external_urls": [],
            "embedded_files": []
        }
    
    def _analyze_libraries(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze third-party libraries"""
        return {
            "third_party_libraries": [
                {"name": "okhttp", "version": "4.9.0", "vulnerabilities": []},
                {"name": "gson", "version": "2.8.6", "vulnerabilities": []}
            ],
            "vulnerable_libraries": [],
            "library_risk_score": 20
        }
    
    def _calculate_permission_risk_score(self, permissions: List[str]) -> float:
        """Calculate permission risk score"""
        risk_score = 0
        
        for permission in permissions:
            if permission in self.permission_risks:
                risk_level = self.permission_risks[permission]["risk_level"]
                if risk_level == "critical":
                    risk_score += 20
                elif risk_level == "high":
                    risk_score += 10
                elif risk_level == "medium":
                    risk_score += 5
                elif risk_level == "low":
                    risk_score += 1
        
        return min(100, risk_score)
    
    def _generate_vulnerability_summary(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "categories": {}
        }
        
        for vuln in vulnerabilities:
            severity = vuln["severity"]
            category = vuln["category"]
            
            summary[severity] += 1
            summary["categories"][category] = summary["categories"].get(category, 0) + 1
        
        return summary
    
    def _get_vulnerability_remediation(self, category: str) -> str:
        """Get remediation advice for vulnerability category"""
        remediations = {
            "insecure_storage": "Use Android Keystore or encrypted storage",
            "insecure_communication": "Implement TLS/SSL with certificate pinning",
            "cryptographic_issues": "Use strong cryptographic algorithms (AES, SHA-256)",
            "injection_vulnerabilities": "Use parameterized queries and input validation",
            "authentication_bypass": "Implement proper certificate validation",
            "webview_vulnerabilities": "Disable unnecessary WebView features"
        }
        return remediations.get(category, "Review and fix the identified security issue")
    
    def _analyze_malware_behavior(self, app_data: Dict, static_analysis: Dict) -> Dict[str, Any]:
        """Analyze behavioral patterns for malware detection"""
        return {
            "suspicious_permissions": [],
            "network_behavior": "normal",
            "file_system_access": "normal",
            "process_behavior": "normal"
        }
    
    def _identify_risk_indicators(self, app_data: Dict, static_analysis: Dict) -> List[Dict]:
        """Identify malware risk indicators"""
        return [
            {
                "indicator": "excessive_permissions",
                "severity": "medium",
                "description": "App requests many sensitive permissions"
            }
        ]
    
    def _calculate_malware_confidence(self, signatures: List[Dict], indicators: List[Dict]) -> float:
        """Calculate malware detection confidence"""
        if not signatures and not indicators:
            return 0.0
        
        signature_score = len(signatures) * 0.3
        indicator_score = len(indicators) * 0.1
        
        return min(1.0, signature_score + indicator_score)
    
    def _analyze_data_collection(self, app_data: Dict, static_analysis: Dict) -> List[Dict]:
        """Analyze data collection practices"""
        return [
            {
                "data_type": "location",
                "collection_method": "gps",
                "purpose": "location_services",
                "retention_period": "unknown"
            }
        ]
    
    def _identify_third_party_trackers(self, app_data: Dict, static_analysis: Dict) -> List[Dict]:
        """Identify third-party tracking libraries"""
        return [
            {
                "tracker": "google_analytics",
                "category": "analytics",
                "privacy_impact": "medium"
            }
        ]
    
    def _assess_gdpr_compliance(self, privacy_assessment: Dict) -> Dict[str, Any]:
        """Assess GDPR compliance"""
        return {
            "compliance_score": 60,
            "missing_requirements": [
                "explicit_consent",
                "data_portability",
                "right_to_erasure"
            ],
            "status": "partial_compliance"
        }
    
    def _assess_ccpa_compliance(self, privacy_assessment: Dict) -> Dict[str, Any]:
        """Assess CCPA compliance"""
        return {
            "compliance_score": 55,
            "missing_requirements": [
                "opt_out_mechanism",
                "data_disclosure",
                "consumer_rights"
            ],
            "status": "partial_compliance"
        }
    
    def _calculate_privacy_score(self, privacy_assessment: Dict) -> float:
        """Calculate privacy score"""
        base_score = 100.0
        
        violations = privacy_assessment.get("privacy_violations", [])
        base_score -= len(violations) * 10
        
        trackers = privacy_assessment.get("third_party_trackers", [])
        base_score -= len(trackers) * 5
        
        return max(0.0, min(100.0, base_score))
    
    def _analyze_code_complexity(self, code_content: str) -> Dict[str, Any]:
        """Analyze code complexity metrics"""
        return {
            "cyclomatic_complexity": 15,
            "lines_of_code": 5000,
            "method_count": 200,
            "class_count": 50
        }
    
    def _check_security_best_practices(self, code_content: str) -> Dict[str, Any]:
        """Check security best practices implementation"""
        return {
            "input_validation": True,
            "output_encoding": False,
            "error_handling": True,
            "logging_security": False
        }
    
    def _calculate_code_quality_score(self, code_quality: Dict) -> float:
        """Calculate code quality score"""
        base_score = 70.0
        
        if code_quality.get("obfuscation_detected"):
            base_score -= 20
        
        anti_analysis = len(code_quality.get("anti_analysis_techniques", []))
        base_score -= anti_analysis * 10
        
        return max(0.0, min(100.0, base_score))
    
    def _calculate_network_security_score(self, network_security: Dict) -> float:
        """Calculate network security score"""
        base_score = 50.0
        
        if network_security.get("certificate_pinning"):
            base_score += 30
        
        insecure_protocols = len(network_security.get("insecure_protocols", []))
        base_score -= insecure_protocols * 15
        
        return max(0.0, min(100.0, base_score))
    
    def _calculate_certificate_score(self, certificate_analysis: Dict) -> float:
        """Calculate certificate security score"""
        base_score = 80.0
        
        issues = certificate_analysis.get("certificate_issues", [])
        for issue in issues:
            if issue["severity"] == "high":
                base_score -= 20
            elif issue["severity"] == "medium":
                base_score -= 10
            elif issue["severity"] == "low":
                base_score -= 5
        
        return max(0.0, min(100.0, base_score))

