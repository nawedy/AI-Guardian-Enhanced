"""
Kotlin-specific vulnerability detection patterns for AI Guardian
"""

import re
from typing import List, Dict, Any

class KotlinVulnerabilityPatterns:
    """Kotlin-specific security vulnerability patterns for Android development"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Kotlin vulnerability patterns"""
        return [
            # Insecure Data Storage
            {
                'id': 'kotlin_insecure_shared_prefs',
                'name': 'Insecure Data Storage - SharedPreferences for Sensitive Data',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'getSharedPreferences\(.*?\)\.edit\(\)\.put.*?(password|token|key|secret|credential)',
                'description': 'Sensitive data stored in SharedPreferences without encryption',
                'fix_suggestion': 'Use EncryptedSharedPreferences or Android Keystore for sensitive data',
                'cwe': 'CWE-312'
            },
            {
                'id': 'kotlin_insecure_file_storage',
                'name': 'Insecure Data Storage - Plain Text File Storage',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'File\(.*?\)\.writeText\(.*?(password|token|key|secret)',
                'description': 'Sensitive data written to file without encryption',
                'fix_suggestion': 'Encrypt sensitive data before writing to files',
                'cwe': 'CWE-312'
            },
            {
                'id': 'kotlin_external_storage_sensitive',
                'name': 'Insecure Data Storage - Sensitive Data on External Storage',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'Environment\.getExternalStorageDirectory\(\).*?(password|token|key|secret)',
                'description': 'Sensitive data stored on external storage accessible to other apps',
                'fix_suggestion': 'Store sensitive data in internal storage or use encryption',
                'cwe': 'CWE-312'
            },
            
            # SQL Injection
            {
                'id': 'kotlin_sql_injection_raw_query',
                'name': 'SQL Injection - Raw Query with String Concatenation',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'rawQuery\s*\(\s*".*?\$.*?"',
                'description': 'SQL injection via string interpolation in raw queries',
                'fix_suggestion': 'Use parameterized queries with ? placeholders',
                'cwe': 'CWE-89'
            },
            {
                'id': 'kotlin_sql_injection_exec_sql',
                'name': 'SQL Injection - execSQL with String Interpolation',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'execSQL\s*\(\s*".*?\$.*?"',
                'description': 'SQL injection in execSQL with string interpolation',
                'fix_suggestion': 'Use parameterized queries or prepared statements',
                'cwe': 'CWE-89'
            },
            
            # Weak Cryptography
            {
                'id': 'kotlin_hardcoded_crypto_key',
                'name': 'Hardcoded Cryptographic Key',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'val\s+.*?(key|secret|password)\s*=\s*"[A-Za-z0-9+/=]{16,}"',
                'description': 'Hardcoded cryptographic key or secret in source code',
                'fix_suggestion': 'Store keys securely in Android Keystore or use key derivation',
                'cwe': 'CWE-798'
            },
            {
                'id': 'kotlin_weak_encryption_des',
                'name': 'Weak Encryption - DES Algorithm',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'Cipher\.getInstance\s*\(\s*"DES',
                'description': 'Use of weak DES encryption algorithm',
                'fix_suggestion': 'Use AES encryption instead of DES',
                'cwe': 'CWE-327'
            },
            {
                'id': 'kotlin_weak_hash_md5',
                'name': 'Weak Hash Function - MD5',
                'severity': 'medium',
                'confidence': 0.9,
                'pattern': r'MessageDigest\.getInstance\s*\(\s*"MD5"',
                'description': 'Use of cryptographically weak MD5 hash function',
                'fix_suggestion': 'Use SHA-256 or stronger hash functions',
                'cwe': 'CWE-327'
            },
            {
                'id': 'kotlin_weak_random',
                'name': 'Weak Random Number Generation - Random()',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'Random\(\)\.next',
                'description': 'Use of weak random number generator for security purposes',
                'fix_suggestion': 'Use SecureRandom for cryptographic randomness',
                'cwe': 'CWE-338'
            },
            
            # Network Security
            {
                'id': 'kotlin_insecure_http',
                'name': 'Insecure Network Communication - HTTP URLs',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'"http://[^"]*"',
                'description': 'Use of insecure HTTP protocol for network communication',
                'fix_suggestion': 'Use HTTPS for all network communications',
                'cwe': 'CWE-319'
            },
            {
                'id': 'kotlin_ssl_verification_disabled',
                'name': 'SSL Certificate Validation Disabled',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'hostnameVerifier\s*=\s*HostnameVerifier\s*\{\s*_,\s*_\s*->\s*true\s*\}',
                'description': 'SSL hostname verification disabled',
                'fix_suggestion': 'Enable proper SSL certificate validation and implement certificate pinning',
                'cwe': 'CWE-295'
            },
            {
                'id': 'kotlin_trust_all_certs',
                'name': 'Trust All SSL Certificates',
                'severity': 'critical',
                'confidence': 0.95,
                'pattern': r'X509TrustManager.*?checkClientTrusted.*?\{\s*\}',
                'description': 'Custom TrustManager that accepts all SSL certificates',
                'fix_suggestion': 'Implement proper certificate validation or use certificate pinning',
                'cwe': 'CWE-295'
            },
            
            # Intent Security
            {
                'id': 'kotlin_implicit_intent_sensitive',
                'name': 'Implicit Intent with Sensitive Data',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'Intent\(\)\.apply\s*\{.*?putExtra\(.*?(password|token|key|secret)',
                'description': 'Sensitive data passed via implicit intents',
                'fix_suggestion': 'Use explicit intents for sensitive data or encrypt the data',
                'cwe': 'CWE-200'
            },
            {
                'id': 'kotlin_exported_activity_no_permission',
                'name': 'Exported Activity Without Permission Check',
                'severity': 'medium',
                'confidence': 0.6,
                'pattern': r'android:exported\s*=\s*"true"(?!.*android:permission)',
                'description': 'Activity exported without proper permission protection',
                'fix_suggestion': 'Add permission requirements or validate caller identity',
                'cwe': 'CWE-284'
            },
            
            # WebView Security
            {
                'id': 'kotlin_webview_javascript_enabled',
                'name': 'WebView JavaScript Enabled Without Validation',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'webSettings\.javaScriptEnabled\s*=\s*true',
                'description': 'JavaScript enabled in WebView without proper content validation',
                'fix_suggestion': 'Validate web content sources and implement CSP headers',
                'cwe': 'CWE-79'
            },
            {
                'id': 'kotlin_webview_file_access',
                'name': 'WebView File System Access Enabled',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'webSettings\.allowFileAccess\s*=\s*true',
                'description': 'WebView configured to allow file system access',
                'fix_suggestion': 'Disable file access unless absolutely necessary',
                'cwe': 'CWE-22'
            },
            {
                'id': 'kotlin_webview_universal_access',
                'name': 'WebView Universal Access From File URLs',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'webSettings\.allowUniversalAccessFromFileURLs\s*=\s*true',
                'description': 'WebView allows universal access from file URLs',
                'fix_suggestion': 'Disable universal access from file URLs to prevent XSS',
                'cwe': 'CWE-79'
            },
            {
                'id': 'kotlin_webview_addjavascriptinterface',
                'name': 'WebView JavaScript Interface Without Validation',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'addJavascriptInterface\s*\(',
                'description': 'JavaScript interface added to WebView without proper validation',
                'fix_suggestion': 'Validate JavaScript calls and use @JavascriptInterface annotation',
                'cwe': 'CWE-94'
            },
            
            # Logging and Debug Information
            {
                'id': 'kotlin_log_sensitive_data',
                'name': 'Sensitive Data in Log Statements',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'Log\.[dviwe]\s*\(.*?(password|token|key|secret|credential)',
                'description': 'Sensitive information logged and potentially accessible',
                'fix_suggestion': 'Remove sensitive data from log statements or use conditional logging',
                'cwe': 'CWE-209'
            },
            {
                'id': 'kotlin_println_sensitive',
                'name': 'Sensitive Data in println Statements',
                'severity': 'low',
                'confidence': 0.8,
                'pattern': r'println\s*\(.*?(password|token|key|secret|credential)',
                'description': 'Sensitive information printed to console',
                'fix_suggestion': 'Remove println statements with sensitive data from production builds',
                'cwe': 'CWE-209'
            },
            
            # Permissions and Access Control
            {
                'id': 'kotlin_dangerous_permission_request',
                'name': 'Dangerous Permission Without Justification',
                'severity': 'low',
                'confidence': 0.6,
                'pattern': r'requestPermissions\s*\(.*?(CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_CONTACTS)',
                'description': 'Requesting dangerous permissions without clear justification',
                'fix_suggestion': 'Ensure dangerous permissions are necessary and explain to users',
                'cwe': 'CWE-250'
            },
            
            # Broadcast Receiver Security
            {
                'id': 'kotlin_unprotected_broadcast',
                'name': 'Unprotected Broadcast Receiver',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'sendBroadcast\s*\(\s*Intent\(\)(?!.*permission)',
                'description': 'Broadcast sent without permission protection',
                'fix_suggestion': 'Add permission parameter to sendBroadcast() calls',
                'cwe': 'CWE-284'
            },
            
            # Content Provider Security
            {
                'id': 'kotlin_content_provider_exported',
                'name': 'Content Provider Exported Without Protection',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'android:exported\s*=\s*"true".*?ContentProvider',
                'description': 'Content Provider exported without proper access controls',
                'fix_suggestion': 'Add permission requirements or implement proper access validation',
                'cwe': 'CWE-284'
            },
            
            # Root Detection Bypass
            {
                'id': 'kotlin_root_detection_weak',
                'name': 'Weak Root Detection',
                'severity': 'low',
                'confidence': 0.6,
                'pattern': r'File\("/system/app/Superuser\.apk"\)\.exists\(\)',
                'description': 'Weak root detection that can be easily bypassed',
                'fix_suggestion': 'Implement multiple root detection methods and runtime checks',
                'cwe': 'CWE-693'
            },
            
            # Backup Security
            {
                'id': 'kotlin_backup_enabled_sensitive',
                'name': 'App Backup Enabled for Sensitive App',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'android:allowBackup\s*=\s*"true"',
                'description': 'App backup enabled which may expose sensitive data',
                'fix_suggestion': 'Disable backup for apps handling sensitive data or use backup rules',
                'cwe': 'CWE-200'
            },
            
            # Deep Link Security
            {
                'id': 'kotlin_deeplink_no_validation',
                'name': 'Deep Link Without Input Validation',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'intent\.data(?!.*validate)',
                'description': 'Deep link data used without proper validation',
                'fix_suggestion': 'Validate and sanitize deep link parameters before use',
                'cwe': 'CWE-20'
            },
            
            # Serialization Security
            {
                'id': 'kotlin_unsafe_serialization',
                'name': 'Unsafe Object Serialization',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'ObjectInputStream\s*\(.*?\)\.readObject\(\)',
                'description': 'Unsafe deserialization of objects from untrusted sources',
                'fix_suggestion': 'Validate serialized data or use safe serialization formats like JSON',
                'cwe': 'CWE-502'
            },
            
            # Certificate Pinning
            {
                'id': 'kotlin_missing_cert_pinning',
                'name': 'Missing Certificate Pinning',
                'severity': 'medium',
                'confidence': 0.5,
                'pattern': r'OkHttpClient\.Builder\(\)(?!.*certificatePinner)',
                'description': 'HTTP client without certificate pinning implementation',
                'fix_suggestion': 'Implement certificate pinning for critical network communications',
                'cwe': 'CWE-295'
            }
        ]
    
    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """Scan Kotlin code for vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for pattern_info in self.patterns:
            pattern = re.compile(pattern_info['pattern'], re.IGNORECASE | re.MULTILINE)
            
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                
                for match in matches:
                    vulnerability = {
                        'id': pattern_info['id'],
                        'name': pattern_info['name'],
                        'severity': pattern_info['severity'],
                        'confidence': pattern_info['confidence'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'description': pattern_info['description'],
                        'fix_suggestion': pattern_info['fix_suggestion'],
                        'cwe': pattern_info.get('cwe', ''),
                        'matched_text': match.group(0)
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def get_supported_extensions(self) -> List[str]:
        """Get supported file extensions for Kotlin"""
        return ['.kt', '.kts']
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get Kotlin language information"""
        return {
            'name': 'Kotlin',
            'version': '1.9.x',
            'extensions': self.get_supported_extensions(),
            'pattern_count': len(self.patterns),
            'categories': [
                'Insecure Data Storage',
                'SQL Injection',
                'Weak Cryptography',
                'Network Security',
                'Intent Security',
                'WebView Security',
                'Logging and Debug Information',
                'Permissions and Access Control',
                'Broadcast Receiver Security',
                'Content Provider Security',
                'Root Detection',
                'Backup Security',
                'Deep Link Security',
                'Serialization Security',
                'Certificate Pinning'
            ]
        }

