"""
Dart/Flutter Security Patterns for AI Guardian
Mobile app security analysis for Dart and Flutter applications
"""

import re
from typing import List, Dict, Any

class DartSecurityPatterns:
    """Dart/Flutter-specific security vulnerability patterns"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Dart/Flutter security patterns"""
        return [
            # Mobile Security Issues
            {
                'id': 'DART_INSECURE_STORAGE',
                'name': 'Insecure Data Storage',
                'pattern': r'SharedPreferences.*putString\([^)]*(?:password|secret|token|key)[^)]*\)|localStorage\[.*(?:password|secret|token|key)',
                'severity': 'high',
                'cwe': 'CWE-922',
                'description': 'Sensitive data stored in insecure local storage',
                'recommendation': 'Use secure storage solutions like flutter_secure_storage',
                'category': 'data_storage'
            },
            {
                'id': 'DART_HARDCODED_SECRETS',
                'name': 'Hardcoded Secrets',
                'pattern': r'(?:apiKey|secretKey|password|token)\s*[:=]\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
                'severity': 'critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded API keys or secrets in source code',
                'recommendation': 'Use environment variables or secure configuration management',
                'category': 'secrets_management'
            },
            {
                'id': 'DART_ROOT_DETECTION_BYPASS',
                'name': 'Missing Root/Jailbreak Detection',
                'pattern': r'(?!.*root_detector|.*jailbreak_detector).*main\(\)',
                'severity': 'medium',
                'cwe': 'CWE-693',
                'description': 'App may run on rooted/jailbroken devices without detection',
                'recommendation': 'Implement root/jailbreak detection for sensitive apps',
                'category': 'device_security'
            },
            
            # Network Security
            {
                'id': 'DART_HTTP_INSECURE',
                'name': 'Insecure HTTP Communication',
                'pattern': r'http://[^"\s]+|HttpClient\(\).*http:|Uri\.parse\(["\']http:',
                'severity': 'medium',
                'cwe': 'CWE-319',
                'description': 'Insecure HTTP communication without encryption',
                'recommendation': 'Use HTTPS for all network communications',
                'category': 'network_security'
            },
            {
                'id': 'DART_SSL_PINNING_MISSING',
                'name': 'Missing SSL Certificate Pinning',
                'pattern': r'HttpClient\(\)(?!.*certificateCallback|.*badCertificateCallback)',
                'severity': 'medium',
                'cwe': 'CWE-295',
                'description': 'HTTP client without SSL certificate pinning',
                'recommendation': 'Implement SSL certificate pinning for enhanced security',
                'category': 'network_security'
            },
            {
                'id': 'DART_CERTIFICATE_VALIDATION_DISABLED',
                'pattern': r'badCertificateCallback:\s*\([^)]*\)\s*=>\s*true|allowBadCertificates:\s*true',
                'severity': 'critical',
                'cwe': 'CWE-295',
                'description': 'SSL certificate validation is disabled',
                'recommendation': 'Enable proper SSL certificate validation',
                'category': 'network_security'
            },
            
            # Input Validation
            {
                'id': 'DART_SQL_INJECTION',
                'name': 'SQL Injection',
                'pattern': r'rawQuery\([^)]*\$[^)]*\)|execute\([^)]*\$[^)]*\)',
                'severity': 'critical',
                'cwe': 'CWE-89',
                'description': 'SQL query with string interpolation may be vulnerable to injection',
                'recommendation': 'Use parameterized queries with ? placeholders',
                'category': 'injection'
            },
            {
                'id': 'DART_PATH_TRAVERSAL',
                'name': 'Path Traversal',
                'pattern': r'File\([^)]*\.\.[^)]*\)|Directory\([^)]*\.\.[^)]*\)',
                'severity': 'high',
                'cwe': 'CWE-22',
                'description': 'Potential path traversal vulnerability',
                'recommendation': 'Validate and sanitize file paths',
                'category': 'path_traversal'
            },
            {
                'id': 'DART_UNVALIDATED_INPUT',
                'name': 'Unvalidated User Input',
                'pattern': r'TextEditingController\(\)\.text(?!\s*\.trim\(\)|\s*\.isEmpty|\s*\.isNotEmpty)',
                'severity': 'medium',
                'cwe': 'CWE-20',
                'description': 'User input used without validation',
                'recommendation': 'Validate and sanitize all user input',
                'category': 'input_validation'
            },
            
            # Cryptographic Issues
            {
                'id': 'DART_WEAK_CRYPTO',
                'name': 'Weak Cryptographic Algorithm',
                'pattern': r'md5|sha1(?!\\d)|des|rc4',
                'severity': 'high',
                'cwe': 'CWE-327',
                'description': 'Use of weak cryptographic algorithms',
                'recommendation': 'Use strong cryptographic algorithms like AES, SHA-256',
                'category': 'cryptography'
            },
            {
                'id': 'DART_WEAK_RANDOM',
                'name': 'Weak Random Number Generation',
                'pattern': r'Random\(\)\.nextInt|Random\(\)\.nextDouble|math\.Random',
                'severity': 'medium',
                'cwe': 'CWE-338',
                'description': 'Use of non-cryptographically secure random number generator',
                'recommendation': 'Use Random.secure() for cryptographic operations',
                'category': 'cryptography'
            },
            {
                'id': 'DART_ENCRYPTION_WITHOUT_AUTH',
                'name': 'Encryption Without Authentication',
                'pattern': r'AES.*ECB|AES.*CBC(?!.*HMAC|.*GCM)',
                'severity': 'high',
                'cwe': 'CWE-353',
                'description': 'Encryption without authentication may be vulnerable to tampering',
                'recommendation': 'Use authenticated encryption modes like GCM or add HMAC',
                'category': 'cryptography'
            },
            
            # Flutter-Specific Issues
            {
                'id': 'FLUTTER_DEBUG_MODE',
                'name': 'Debug Mode in Production',
                'pattern': r'kDebugMode\s*==\s*true|assert\(|debugPrint\(',
                'severity': 'low',
                'cwe': 'CWE-489',
                'description': 'Debug code may be present in production builds',
                'recommendation': 'Remove debug code and assertions from production builds',
                'category': 'debug_info'
            },
            {
                'id': 'FLUTTER_WEBVIEW_JAVASCRIPT',
                'name': 'WebView JavaScript Enabled',
                'pattern': r'WebView.*javascriptMode:\s*JavascriptMode\.unrestricted',
                'severity': 'medium',
                'cwe': 'CWE-79',
                'description': 'WebView with unrestricted JavaScript execution',
                'recommendation': 'Restrict JavaScript execution or validate content sources',
                'category': 'webview_security'
            },
            {
                'id': 'FLUTTER_DEEP_LINK_VALIDATION',
                'name': 'Unvalidated Deep Links',
                'pattern': r'onGenerateRoute.*settings\.name(?!\s*\.startsWith|\s*\.contains)',
                'severity': 'medium',
                'cwe': 'CWE-20',
                'description': 'Deep link routes not properly validated',
                'recommendation': 'Validate deep link parameters and routes',
                'category': 'deep_links'
            },
            
            # Permission and Privacy
            {
                'id': 'DART_EXCESSIVE_PERMISSIONS',
                'name': 'Excessive Permissions',
                'pattern': r'Permission\.(camera|microphone|location|contacts|storage)(?!.*request)',
                'severity': 'medium',
                'cwe': 'CWE-250',
                'description': 'Sensitive permissions used without proper request handling',
                'recommendation': 'Request permissions only when needed and handle denials',
                'category': 'permissions'
            },
            {
                'id': 'DART_LOCATION_ALWAYS',
                'name': 'Always-On Location Access',
                'pattern': r'LocationPermission\.always|location.*always',
                'severity': 'medium',
                'cwe': 'CWE-250',
                'description': 'App requests always-on location access',
                'recommendation': 'Use when-in-use location permission when possible',
                'category': 'privacy'
            },
            {
                'id': 'DART_BIOMETRIC_FALLBACK',
                'name': 'Insecure Biometric Fallback',
                'pattern': r'authenticateWithBiometrics.*fallbackToDeviceCredentials:\s*true',
                'severity': 'medium',
                'cwe': 'CWE-287',
                'description': 'Biometric authentication with insecure fallback',
                'recommendation': 'Use secure fallback mechanisms for biometric authentication',
                'category': 'authentication'
            },
            
            # Code Quality and Security
            {
                'id': 'DART_DYNAMIC_TYPE_USAGE',
                'name': 'Dynamic Type Usage',
                'pattern': r'dynamic\s+\w+|var\s+\w+\s*=\s*json\.decode',
                'severity': 'low',
                'cwe': 'CWE-704',
                'description': 'Use of dynamic types may hide type safety issues',
                'recommendation': 'Use specific types for better type safety',
                'category': 'type_safety'
            },
            {
                'id': 'DART_NULL_SAFETY_BYPASS',
                'name': 'Null Safety Bypass',
                'pattern': r'!\s*(?:\.|$)|as\s+\w+(?!\?)',
                'severity': 'medium',
                'cwe': 'CWE-476',
                'description': 'Null safety bypassed with force unwrapping',
                'recommendation': 'Use safe null handling with null-aware operators',
                'category': 'null_safety'
            },
            {
                'id': 'DART_EXCEPTION_SWALLOWING',
                'name': 'Exception Swallowing',
                'pattern': r'catch\s*\([^)]*\)\s*\{\s*\}|on\s+\w+\s*\{\s*\}',
                'severity': 'medium',
                'cwe': 'CWE-248',
                'description': 'Empty catch blocks may hide important errors',
                'recommendation': 'Handle exceptions appropriately or log them',
                'category': 'error_handling'
            },
            
            # Platform Channel Security
            {
                'id': 'DART_PLATFORM_CHANNEL_VALIDATION',
                'name': 'Unvalidated Platform Channel Data',
                'pattern': r'MethodChannel.*invokeMethod\([^)]*\)(?!\s*\.then|\s*\.catchError)',
                'severity': 'medium',
                'cwe': 'CWE-20',
                'description': 'Platform channel method calls without error handling',
                'recommendation': 'Validate platform channel data and handle errors',
                'category': 'platform_channels'
            },
            
            # Firebase Security
            {
                'id': 'DART_FIREBASE_RULES_PERMISSIVE',
                'name': 'Permissive Firebase Rules',
                'pattern': r'allow\s+read,\s*write:\s*if\s+true|allow\s+read,\s*write;',
                'severity': 'critical',
                'cwe': 'CWE-284',
                'description': 'Overly permissive Firebase security rules',
                'recommendation': 'Implement proper Firebase security rules',
                'category': 'firebase_security'
            },
            {
                'id': 'DART_FIREBASE_ADMIN_SDK',
                'name': 'Firebase Admin SDK in Client',
                'pattern': r'firebase_admin|FirebaseAdmin',
                'severity': 'critical',
                'cwe': 'CWE-250',
                'description': 'Firebase Admin SDK should not be used in client applications',
                'recommendation': 'Use Firebase Admin SDK only on secure servers',
                'category': 'firebase_security'
            },
            
            # State Management Security
            {
                'id': 'DART_SENSITIVE_STATE_EXPOSURE',
                'name': 'Sensitive Data in State',
                'pattern': r'class.*State.*\{[^}]*(?:password|secret|token|key)[^}]*\}',
                'severity': 'medium',
                'cwe': 'CWE-200',
                'description': 'Sensitive data stored in widget state',
                'recommendation': 'Avoid storing sensitive data in widget state',
                'category': 'state_management'
            },
            
            # Logging and Information Disclosure
            {
                'id': 'DART_SENSITIVE_LOGGING',
                'name': 'Sensitive Information in Logs',
                'pattern': r'print\([^)]*(?:password|secret|token|key)[^)]*\)|log\([^)]*(?:password|secret|token|key)[^)]*\)',
                'severity': 'medium',
                'cwe': 'CWE-532',
                'description': 'Sensitive information in log statements',
                'recommendation': 'Avoid logging sensitive information',
                'category': 'information_disclosure'
            },
            
            # Package Security
            {
                'id': 'DART_OUTDATED_DEPENDENCIES',
                'name': 'Outdated Dependencies',
                'pattern': r'^\s*\w+:\s*\^?[0-9]+\.[0-9]+\.[0-9]+\s*$',
                'severity': 'low',
                'cwe': 'CWE-1104',
                'description': 'Potentially outdated package dependencies',
                'recommendation': 'Regularly update dependencies and check for security advisories',
                'category': 'dependencies'
            },
            
            # Widget Security
            {
                'id': 'DART_UNSAFE_HTML_WIDGET',
                'name': 'Unsafe HTML Widget',
                'pattern': r'Html\([^)]*data:\s*[^)]*\$[^)]*\)',
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'HTML widget with dynamic content may be vulnerable to XSS',
                'recommendation': 'Sanitize HTML content or use safe alternatives',
                'category': 'widget_security'
            }
        ]
    
    def scan_code(self, code: str, filename: str = '') -> List[Dict[str, Any]]:
        """Scan Dart/Flutter code for security vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for pattern_info in self.patterns:
            pattern = pattern_info['pattern']
            compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for line_num, line in enumerate(lines, 1):
                matches = compiled_pattern.finditer(line)
                for match in matches:
                    # Skip if in comments
                    if self._is_in_comment(line, match.start()):
                        continue
                    
                    vulnerability = {
                        'type': pattern_info['name'],
                        'severity': pattern_info['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'description': pattern_info['description'],
                        'recommendation': pattern_info['recommendation'],
                        'cwe': pattern_info['cwe'],
                        'category': pattern_info['category'],
                        'code_snippet': line.strip(),
                        'pattern_id': pattern_info['id'],
                        'confidence': self._calculate_confidence(pattern_info, line, match, filename)
                    }
                    vulnerabilities.append(vulnerability)
        
        # Add Dart/Flutter-specific advanced analysis
        vulnerabilities.extend(self._advanced_dart_analysis(code, lines, filename))
        
        return vulnerabilities
    
    def _is_in_comment(self, line: str, position: int) -> bool:
        """Check if position is within a comment"""
        # Single line comment
        comment_pos = line.find('//')
        if comment_pos != -1 and position > comment_pos:
            return True
        
        # Multi-line comments are more complex to handle properly
        # This is a simplified check
        return False
    
    def _calculate_confidence(self, pattern_info: Dict, line: str, match: re.Match, filename: str) -> float:
        """Calculate confidence score for the vulnerability"""
        base_confidence = 0.8
        
        # Increase confidence for critical patterns
        if pattern_info['severity'] == 'critical':
            base_confidence = 0.95
        elif pattern_info['severity'] == 'high':
            base_confidence = 0.85
        
        # Decrease confidence if in test files
        if 'test' in filename.lower() or '_test.dart' in filename:
            base_confidence *= 0.6
        
        # Increase confidence for Flutter-specific patterns
        if 'flutter' in pattern_info['id'].lower() and 'flutter' in line.lower():
            base_confidence = min(0.95, base_confidence + 0.1)
        
        # Increase confidence for mobile-specific security issues
        if pattern_info['category'] in ['data_storage', 'permissions', 'device_security']:
            base_confidence = min(0.90, base_confidence + 0.05)
        
        return round(base_confidence, 2)
    
    def _advanced_dart_analysis(self, code: str, lines: List[str], filename: str) -> List[Dict[str, Any]]:
        """Perform advanced Dart/Flutter-specific security analysis"""
        vulnerabilities = []
        
        # Check for missing app transport security
        if 'ios' in filename.lower() or 'Info.plist' in filename:
            ats_pattern = r'NSAppTransportSecurity.*NSAllowsArbitraryLoads.*true'
            for line_num, line in enumerate(lines, 1):
                if re.search(ats_pattern, line):
                    vulnerabilities.append({
                        'type': 'App Transport Security Disabled',
                        'severity': 'high',
                        'line': line_num,
                        'column': 1,
                        'description': 'App Transport Security is disabled, allowing insecure connections',
                        'recommendation': 'Enable ATS and use HTTPS for all network communications',
                        'cwe': 'CWE-319',
                        'category': 'network_security',
                        'code_snippet': line.strip(),
                        'pattern_id': 'DART_ATS_DISABLED',
                        'confidence': 0.90
                    })
        
        # Check for insecure Android network security config
        if 'android' in filename.lower() and 'network_security_config' in filename:
            insecure_config_pattern = r'cleartextTrafficPermitted="true"|trust-anchors.*user'
            for line_num, line in enumerate(lines, 1):
                if re.search(insecure_config_pattern, line):
                    vulnerabilities.append({
                        'type': 'Insecure Network Security Configuration',
                        'severity': 'high',
                        'line': line_num,
                        'column': 1,
                        'description': 'Android network security configuration allows insecure connections',
                        'recommendation': 'Restrict cleartext traffic and use secure trust anchors',
                        'cwe': 'CWE-319',
                        'category': 'network_security',
                        'code_snippet': line.strip(),
                        'pattern_id': 'DART_ANDROID_INSECURE_CONFIG',
                        'confidence': 0.90
                    })
        
        # Check for potential memory leaks in StreamSubscription
        stream_pattern = r'StreamSubscription.*=.*listen\([^)]*\)(?!\s*\..\s*cancel\(\))'
        for line_num, line in enumerate(lines, 1):
            if re.search(stream_pattern, line):
                vulnerabilities.append({
                    'type': 'Potential Memory Leak in Stream Subscription',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'StreamSubscription may not be properly cancelled',
                    'recommendation': 'Cancel StreamSubscription in dispose() method',
                    'cwe': 'CWE-401',
                    'category': 'resource_management',
                    'code_snippet': line.strip(),
                    'pattern_id': 'DART_STREAM_LEAK',
                    'confidence': 0.75
                })
        
        # Check for insecure random number generation in security contexts
        security_random_pattern = r'(?:token|key|nonce|salt).*Random\(\)\.next'
        for line_num, line in enumerate(lines, 1):
            if re.search(security_random_pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Insecure Random in Security Context',
                    'severity': 'high',
                    'line': line_num,
                    'column': 1,
                    'description': 'Non-cryptographically secure random used for security-sensitive operations',
                    'recommendation': 'Use Random.secure() for cryptographic operations',
                    'cwe': 'CWE-338',
                    'category': 'cryptography',
                    'code_snippet': line.strip(),
                    'pattern_id': 'DART_INSECURE_RANDOM_SECURITY',
                    'confidence': 0.85
                })
        
        # Check for potential widget rebuild performance issues that could lead to DoS
        expensive_build_pattern = r'build\([^)]*\).*\{[^}]*(?:for\s*\([^)]*\)|while\s*\([^)]*\)|List\.generate\([^)]*\))[^}]*\}'
        for line_num, line in enumerate(lines, 1):
            if re.search(expensive_build_pattern, line):
                vulnerabilities.append({
                    'type': 'Expensive Operations in Widget Build',
                    'severity': 'low',
                    'line': line_num,
                    'column': 1,
                    'description': 'Expensive operations in build method may cause performance issues',
                    'recommendation': 'Move expensive operations outside build method or use memoization',
                    'cwe': 'CWE-400',
                    'category': 'performance',
                    'code_snippet': line.strip(),
                    'pattern_id': 'DART_EXPENSIVE_BUILD',
                    'confidence': 0.65
                })
        
        return vulnerabilities
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get information about Dart/Flutter language support"""
        return {
            'language': 'dart',
            'framework': 'flutter',
            'version': '1.0.0',
            'patterns_count': len(self.patterns),
            'categories': list(set(p['category'] for p in self.patterns)),
            'severity_levels': list(set(p['severity'] for p in self.patterns)),
            'platforms': ['iOS', 'Android', 'Web', 'Desktop'],
            'description': 'Comprehensive Dart/Flutter security analysis with mobile app focus'
        }

