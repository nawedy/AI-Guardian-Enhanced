"""
Swift-specific vulnerability detection patterns for AI Guardian
"""

import re
from typing import List, Dict, Any

class SwiftVulnerabilityPatterns:
    """Swift-specific security vulnerability patterns for iOS/macOS development"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Swift vulnerability patterns"""
        return [
            # Insecure Data Storage
            {
                'id': 'swift_insecure_userdefaults',
                'name': 'Insecure Data Storage - UserDefaults for Sensitive Data',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'UserDefaults\.standard\.set\s*\(.*?(password|token|key|secret|credential)',
                'description': 'Sensitive data stored in UserDefaults without encryption',
                'fix_suggestion': 'Use Keychain Services for sensitive data storage',
                'cwe': 'CWE-312'
            },
            {
                'id': 'swift_insecure_file_storage',
                'name': 'Insecure Data Storage - Plain Text File Storage',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'\.write\(to:\s*.*?\)\s*.*?(password|token|key|secret)',
                'description': 'Sensitive data written to file without encryption',
                'fix_suggestion': 'Encrypt sensitive data before writing to files',
                'cwe': 'CWE-312'
            },
            
            # Weak Cryptography
            {
                'id': 'swift_weak_random',
                'name': 'Weak Random Number Generation - arc4random()',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'arc4random\(\)',
                'description': 'Use of potentially weak random number generator',
                'fix_suggestion': 'Use SecRandomCopyBytes() for cryptographic randomness',
                'cwe': 'CWE-338'
            },
            {
                'id': 'swift_hardcoded_crypto_key',
                'name': 'Hardcoded Cryptographic Key',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'let\s+.*?(key|secret|password)\s*=\s*"[A-Za-z0-9+/=]{16,}"',
                'description': 'Hardcoded cryptographic key or secret in source code',
                'fix_suggestion': 'Store keys securely in Keychain or use key derivation',
                'cwe': 'CWE-798'
            },
            {
                'id': 'swift_weak_encryption_des',
                'name': 'Weak Encryption - DES Algorithm',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'kCCAlgorithmDES',
                'description': 'Use of weak DES encryption algorithm',
                'fix_suggestion': 'Use AES encryption instead of DES',
                'cwe': 'CWE-327'
            },
            {
                'id': 'swift_weak_hash_md5',
                'name': 'Weak Hash Function - MD5',
                'severity': 'medium',
                'confidence': 0.9,
                'pattern': r'CC_MD5',
                'description': 'Use of cryptographically weak MD5 hash function',
                'fix_suggestion': 'Use SHA-256 or stronger hash functions',
                'cwe': 'CWE-327'
            },
            
            # Network Security
            {
                'id': 'swift_insecure_http',
                'name': 'Insecure Network Communication - HTTP URLs',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'"http://[^"]*"',
                'description': 'Use of insecure HTTP protocol for network communication',
                'fix_suggestion': 'Use HTTPS for all network communications',
                'cwe': 'CWE-319'
            },
            {
                'id': 'swift_ssl_pinning_disabled',
                'name': 'SSL Certificate Validation Disabled',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'\.allowsAnyHTTPSCertificate\s*=\s*true',
                'description': 'SSL certificate validation disabled',
                'fix_suggestion': 'Enable proper SSL certificate validation and implement certificate pinning',
                'cwe': 'CWE-295'
            },
            {
                'id': 'swift_url_session_insecure',
                'name': 'Insecure URLSession Configuration',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'URLSessionConfiguration\.default\.tlsMinimumSupportedProtocol\s*=\s*\.tlsProtocol10',
                'description': 'Insecure TLS protocol version configured',
                'fix_suggestion': 'Use TLS 1.2 or higher for secure communications',
                'cwe': 'CWE-326'
            },
            
            # Input Validation
            {
                'id': 'swift_sql_injection_sqlite',
                'name': 'SQL Injection - SQLite String Interpolation',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'sqlite3_exec\s*\(.*?".*?\\\(.*?\).*?"',
                'description': 'SQL injection via string interpolation in SQLite queries',
                'fix_suggestion': 'Use parameterized queries with sqlite3_prepare_v2',
                'cwe': 'CWE-89'
            },
            {
                'id': 'swift_path_traversal',
                'name': 'Path Traversal - Unvalidated File Paths',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'FileManager\.default\.contents\(atPath:\s*.*?\+.*?\)',
                'description': 'Path traversal vulnerability in file operations',
                'fix_suggestion': 'Validate and sanitize file paths, use URL(fileURLWithPath:) safely',
                'cwe': 'CWE-22'
            },
            
            # Authentication and Authorization
            {
                'id': 'swift_biometric_fallback_insecure',
                'name': 'Insecure Biometric Authentication Fallback',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'LAPolicy\.deviceOwnerAuthentication(?!WithBiometrics)',
                'description': 'Biometric authentication allows insecure fallback methods',
                'fix_suggestion': 'Use LAPolicy.deviceOwnerAuthenticationWithBiometrics for biometric-only auth',
                'cwe': 'CWE-287'
            },
            {
                'id': 'swift_keychain_no_access_control',
                'name': 'Keychain Item Without Access Control',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'SecItemAdd\s*\(.*?\)(?!.*kSecAccessControl)',
                'description': 'Keychain item stored without proper access control',
                'fix_suggestion': 'Add kSecAccessControl with appropriate protection level',
                'cwe': 'CWE-284'
            },
            
            # Code Quality and Logic Issues
            {
                'id': 'swift_force_unwrap_optional',
                'name': 'Unsafe Force Unwrapping - Runtime Crash Risk',
                'severity': 'medium',
                'confidence': 0.6,
                'pattern': r'[a-zA-Z_][a-zA-Z0-9_]*!(?!\s*=)',
                'description': 'Force unwrapping optional values can cause runtime crashes',
                'fix_suggestion': 'Use optional binding (if let) or nil coalescing operator (??)',
                'cwe': 'CWE-476'
            },
            {
                'id': 'swift_debug_logging',
                'name': 'Debug Information Disclosure - Print Statements',
                'severity': 'low',
                'confidence': 0.8,
                'pattern': r'print\s*\(.*?(password|token|key|secret|credential)',
                'description': 'Sensitive information logged via print statements',
                'fix_suggestion': 'Remove debug print statements or use conditional compilation',
                'cwe': 'CWE-209'
            },
            {
                'id': 'swift_nslog_sensitive',
                'name': 'Debug Information Disclosure - NSLog with Sensitive Data',
                'severity': 'low',
                'confidence': 0.8,
                'pattern': r'NSLog\s*\(.*?(password|token|key|secret|credential)',
                'description': 'Sensitive information logged via NSLog',
                'fix_suggestion': 'Remove NSLog statements with sensitive data from production builds',
                'cwe': 'CWE-209'
            },
            
            # Memory Management
            {
                'id': 'swift_unsafe_pointer_access',
                'name': 'Unsafe Memory Access - UnsafePointer Usage',
                'severity': 'high',
                'confidence': 0.7,
                'pattern': r'UnsafePointer<.*?>\.pointee',
                'description': 'Unsafe memory access that could lead to crashes or security issues',
                'fix_suggestion': 'Use safe Swift alternatives or add proper bounds checking',
                'cwe': 'CWE-119'
            },
            {
                'id': 'swift_unsafe_mutable_pointer',
                'name': 'Unsafe Memory Modification - UnsafeMutablePointer',
                'severity': 'high',
                'confidence': 0.7,
                'pattern': r'UnsafeMutablePointer<.*?>\.pointee\s*=',
                'description': 'Unsafe memory modification that could lead to security vulnerabilities',
                'fix_suggestion': 'Use safe Swift memory management patterns',
                'cwe': 'CWE-119'
            },
            
            # WebView Security
            {
                'id': 'swift_webview_javascript_enabled',
                'name': 'WebView JavaScript Injection Risk',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'webView\.evaluateJavaScript\s*\(.*?\+.*?\)',
                'description': 'JavaScript injection risk in WebView with dynamic content',
                'fix_suggestion': 'Sanitize input before JavaScript evaluation or use message handlers',
                'cwe': 'CWE-94'
            },
            {
                'id': 'swift_webview_file_access',
                'name': 'WebView File System Access Enabled',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'allowsLocalFileAccess\s*=\s*true',
                'description': 'WebView configured to allow local file system access',
                'fix_suggestion': 'Disable local file access unless absolutely necessary',
                'cwe': 'CWE-22'
            },
            
            # URL Scheme Handling
            {
                'id': 'swift_url_scheme_validation',
                'name': 'URL Scheme Handling Without Validation',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'application\s*\(.*?open\s+url:.*?\)(?!.*validate)',
                'description': 'URL scheme handling without proper validation',
                'fix_suggestion': 'Validate URL schemes and parameters before processing',
                'cwe': 'CWE-20'
            },
            
            # Jailbreak Detection Bypass
            {
                'id': 'swift_jailbreak_detection_weak',
                'name': 'Weak Jailbreak Detection',
                'severity': 'low',
                'confidence': 0.6,
                'pattern': r'FileManager\.default\.fileExists\(atPath:\s*"/Applications/Cydia\.app"\)',
                'description': 'Weak jailbreak detection that can be easily bypassed',
                'fix_suggestion': 'Implement multiple jailbreak detection methods and runtime checks',
                'cwe': 'CWE-693'
            },
            
            # Certificate Pinning
            {
                'id': 'swift_missing_cert_pinning',
                'name': 'Missing Certificate Pinning',
                'severity': 'medium',
                'confidence': 0.5,
                'pattern': r'URLSession\.shared\.dataTask(?!.*pinnedCertificates)',
                'description': 'Network requests without certificate pinning implementation',
                'fix_suggestion': 'Implement certificate pinning for critical network communications',
                'cwe': 'CWE-295'
            },
            
            # Backup and Screenshot Protection
            {
                'id': 'swift_screenshot_protection_missing',
                'name': 'Missing Screenshot Protection',
                'severity': 'low',
                'confidence': 0.6,
                'pattern': r'applicationDidEnterBackground(?!.*UIImageView)',
                'description': 'Missing protection against screenshots in background state',
                'fix_suggestion': 'Add overlay view when app enters background to prevent sensitive data screenshots',
                'cwe': 'CWE-200'
            },
            
            # Runtime Application Self-Protection (RASP)
            {
                'id': 'swift_anti_debugging_missing',
                'name': 'Missing Anti-Debugging Protection',
                'severity': 'low',
                'confidence': 0.4,
                'pattern': r'func\s+.*?main\s*\(',
                'description': 'Application lacks anti-debugging protection mechanisms',
                'fix_suggestion': 'Implement anti-debugging checks and runtime application self-protection',
                'cwe': 'CWE-693'
            }
        ]
    
    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """Scan Swift code for vulnerabilities"""
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
        """Get supported file extensions for Swift"""
        return ['.swift']
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get Swift language information"""
        return {
            'name': 'Swift',
            'version': '5.x',
            'extensions': self.get_supported_extensions(),
            'pattern_count': len(self.patterns),
            'categories': [
                'Insecure Data Storage',
                'Weak Cryptography',
                'Network Security',
                'Input Validation',
                'Authentication and Authorization',
                'Code Quality and Logic Issues',
                'Memory Management',
                'WebView Security',
                'URL Scheme Handling',
                'Jailbreak Detection',
                'Certificate Pinning',
                'Backup and Screenshot Protection',
                'Runtime Application Self-Protection'
            ]
        }

