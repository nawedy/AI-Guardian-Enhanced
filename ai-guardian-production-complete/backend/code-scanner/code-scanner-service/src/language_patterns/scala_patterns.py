"""
Scala Security Patterns for AI Guardian
Advanced functional programming and JVM security analysis for Scala applications
"""

import re
from typing import List, Dict, Any

class ScalaSecurityPatterns:
    """Scala-specific security vulnerability patterns"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Scala security patterns"""
        return [
            # Injection Vulnerabilities
            {
                'id': 'SCALA_SQL_INJECTION',
                'name': 'SQL Injection',
                'pattern': r'sql"[^"]*\$\{[^}]+\}|s"SELECT.*\$\{|s"INSERT.*\$\{|s"UPDATE.*\$\{|s"DELETE.*\$\{',
                'severity': 'critical',
                'cwe': 'CWE-89',
                'description': 'SQL query with string interpolation may be vulnerable to injection',
                'recommendation': 'Use parameterized queries or prepared statements',
                'category': 'injection'
            },
            {
                'id': 'SCALA_COMMAND_INJECTION',
                'pattern': r'Process\([^)]*\$\{|Runtime\.getRuntime\(\)\.exec\([^)]*\$\{|".*\$\{.*"\.!',
                'severity': 'critical',
                'cwe': 'CWE-78',
                'description': 'Command execution with user input may allow command injection',
                'recommendation': 'Sanitize input and use safe command execution methods',
                'category': 'injection'
            },
            {
                'id': 'SCALA_LDAP_INJECTION',
                'pattern': r'new\s+InitialDirContext.*\$\{|search\([^)]*\$\{',
                'severity': 'high',
                'cwe': 'CWE-90',
                'description': 'LDAP query with user input may be vulnerable to injection',
                'recommendation': 'Use parameterized LDAP queries and input validation',
                'category': 'injection'
            },
            
            # Deserialization Issues
            {
                'id': 'SCALA_UNSAFE_DESERIALIZATION',
                'pattern': r'ObjectInputStream|readObject\(\)|Java\.deserialize|pickle\.loads',
                'severity': 'critical',
                'cwe': 'CWE-502',
                'description': 'Unsafe deserialization can lead to remote code execution',
                'recommendation': 'Use safe serialization libraries and validate input',
                'category': 'deserialization'
            },
            {
                'id': 'SCALA_AKKA_SERIALIZATION',
                'pattern': r'JavaSerializer|akka\.serialization\.JavaSerializer',
                'severity': 'high',
                'cwe': 'CWE-502',
                'description': 'Akka Java serialization is vulnerable to deserialization attacks',
                'recommendation': 'Use Akka\'s safer serialization options like Jackson or Protobuf',
                'category': 'deserialization'
            },
            
            # Cryptographic Issues
            {
                'id': 'SCALA_WEAK_CRYPTO',
                'pattern': r'DES|RC4|MD5|SHA1(?!\\d)|MessageDigest\.getInstance\("MD5"\)|MessageDigest\.getInstance\("SHA1"\)',
                'severity': 'high',
                'cwe': 'CWE-327',
                'description': 'Use of weak cryptographic algorithms',
                'recommendation': 'Use strong cryptographic algorithms like AES, SHA-256, or SHA-3',
                'category': 'cryptography'
            },
            {
                'id': 'SCALA_HARDCODED_CRYPTO',
                'pattern': r'(?:key|secret|password|token)\s*=\s*"[a-zA-Z0-9+/=]{16,}"|(?:key|secret|password|token)\s*=\s*\'[a-zA-Z0-9+/=]{16,}\'',
                'severity': 'critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded cryptographic key or secret',
                'recommendation': 'Load secrets from environment variables or secure configuration',
                'category': 'cryptography'
            },
            {
                'id': 'SCALA_WEAK_RANDOM',
                'pattern': r'scala\.util\.Random|new\s+Random\(\)|Math\.random',
                'severity': 'medium',
                'cwe': 'CWE-338',
                'description': 'Use of non-cryptographically secure random number generator',
                'recommendation': 'Use SecureRandom for cryptographic operations',
                'category': 'cryptography'
            },
            
            # Input Validation
            {
                'id': 'SCALA_UNVALIDATED_INPUT',
                'pattern': r'request\.getParameter\([^)]+\)(?!\s*\.filter|\s*\.map|\s*\.validate)',
                'severity': 'medium',
                'cwe': 'CWE-20',
                'description': 'User input used without validation',
                'recommendation': 'Validate and sanitize all user input',
                'category': 'input_validation'
            },
            {
                'id': 'SCALA_PATH_TRAVERSAL',
                'pattern': r'new\s+File\([^)]*\.\.[^)]*\)|Paths\.get\([^)]*\.\.[^)]*\)',
                'severity': 'high',
                'cwe': 'CWE-22',
                'description': 'Potential path traversal vulnerability',
                'recommendation': 'Validate file paths and use secure file access methods',
                'category': 'path_traversal'
            },
            
            # XSS and Output Encoding
            {
                'id': 'SCALA_XSS_VULNERABILITY',
                'pattern': r'Html\([^)]*\$\{|raw\([^)]*\$\{|@Html\([^)]*\$\{',
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'Potential XSS vulnerability in HTML output',
                'recommendation': 'Use proper HTML encoding and sanitization',
                'category': 'xss'
            },
            {
                'id': 'SCALA_PLAY_UNSAFE_HTML',
                'pattern': r'views\.html\..*\.render\([^)]*user_input[^)]*\)(?!\.toString\.escape)',
                'severity': 'medium',
                'cwe': 'CWE-79',
                'description': 'Unescaped user input in Play Framework templates',
                'recommendation': 'Use Play\'s built-in HTML escaping mechanisms',
                'category': 'xss'
            },
            
            # Authentication and Authorization
            {
                'id': 'SCALA_WEAK_SESSION',
                'pattern': r'session\([^)]*\)\s*=\s*[^;]*(?!\.signed|\.encrypted)',
                'severity': 'medium',
                'cwe': 'CWE-384',
                'description': 'Session data stored without encryption or signing',
                'recommendation': 'Use signed or encrypted session storage',
                'category': 'authentication'
            },
            {
                'id': 'SCALA_HARDCODED_CREDENTIALS',
                'pattern': r'(?:username|password|apikey)\s*=\s*"[^"]+"|(?:username|password|apikey)\s*=\s*\'[^\']+\'',
                'severity': 'high',
                'cwe': 'CWE-798',
                'description': 'Hardcoded credentials in source code',
                'recommendation': 'Use environment variables or secure configuration management',
                'category': 'authentication'
            },
            
            # Concurrency Issues
            {
                'id': 'SCALA_RACE_CONDITION',
                'pattern': r'var\s+\w+.*=.*(?!@volatile)|mutable\.Map\[|mutable\.Set\[|mutable\.Buffer\[',
                'severity': 'medium',
                'cwe': 'CWE-362',
                'description': 'Mutable shared state may cause race conditions',
                'recommendation': 'Use immutable data structures or proper synchronization',
                'category': 'concurrency'
            },
            {
                'id': 'SCALA_ACTOR_UNSAFE_STATE',
                'pattern': r'class.*extends\s+Actor.*var\s+|object.*extends\s+Actor.*var\s+',
                'severity': 'medium',
                'cwe': 'CWE-362',
                'description': 'Mutable state in Actor may cause concurrency issues',
                'recommendation': 'Use immutable state and message passing in Actors',
                'category': 'concurrency'
            },
            
            # Reflection and Dynamic Code
            {
                'id': 'SCALA_UNSAFE_REFLECTION',
                'pattern': r'Class\.forName\([^)]*user_input[^)]*\)|classOf\[[^]]*user_input[^]]*\]',
                'severity': 'high',
                'cwe': 'CWE-470',
                'description': 'Dynamic class loading with user input',
                'recommendation': 'Validate class names and use whitelist approach',
                'category': 'reflection'
            },
            {
                'id': 'SCALA_EVAL_INJECTION',
                'pattern': r'eval\([^)]*\$\{|compile\([^)]*\$\{|interpret\([^)]*\$\{',
                'severity': 'critical',
                'cwe': 'CWE-95',
                'description': 'Dynamic code evaluation with user input',
                'recommendation': 'Avoid dynamic code evaluation or use sandboxed environments',
                'category': 'code_injection'
            },
            
            # File System Security
            {
                'id': 'SCALA_INSECURE_FILE_UPLOAD',
                'pattern': r'MultipartFormData.*file\.ref\.moveTo|file\.ref\.copyTo',
                'severity': 'high',
                'cwe': 'CWE-434',
                'description': 'File upload without proper validation',
                'recommendation': 'Validate file types, sizes, and use secure file storage',
                'category': 'file_upload'
            },
            {
                'id': 'SCALA_TEMP_FILE_EXPOSURE',
                'pattern': r'File\.createTempFile\([^)]*\)(?!\.deleteOnExit)',
                'severity': 'medium',
                'cwe': 'CWE-377',
                'description': 'Temporary file created without proper cleanup',
                'recommendation': 'Ensure temporary files are properly cleaned up',
                'category': 'file_system'
            },
            
            # Network Security
            {
                'id': 'SCALA_INSECURE_HTTP',
                'pattern': r'http://[^"\'\\s]+|HttpURLConnection.*http:|WS\.url\("http:',
                'severity': 'medium',
                'cwe': 'CWE-319',
                'description': 'Insecure HTTP communication',
                'recommendation': 'Use HTTPS for sensitive communications',
                'category': 'network_security'
            },
            {
                'id': 'SCALA_SSL_VERIFICATION_DISABLED',
                'pattern': r'setHostnameVerifier.*ALLOW_ALL|TrustManager.*checkServerTrusted.*\{\s*\}',
                'severity': 'critical',
                'cwe': 'CWE-295',
                'description': 'SSL/TLS certificate verification disabled',
                'recommendation': 'Enable proper SSL/TLS certificate verification',
                'category': 'network_security'
            },
            
            # Play Framework Specific
            {
                'id': 'SCALA_PLAY_CSRF_DISABLED',
                'pattern': r'csrf\.check\s*=\s*false|CSRFFilter.*disable',
                'severity': 'high',
                'cwe': 'CWE-352',
                'description': 'CSRF protection disabled in Play Framework',
                'recommendation': 'Enable CSRF protection for state-changing operations',
                'category': 'csrf'
            },
            {
                'id': 'SCALA_PLAY_UNSAFE_REDIRECT',
                'pattern': r'Redirect\([^)]*request\.|Redirect\([^)]*user_input',
                'severity': 'medium',
                'cwe': 'CWE-601',
                'description': 'Unvalidated redirect in Play Framework',
                'recommendation': 'Validate redirect URLs against whitelist',
                'category': 'redirect'
            },
            
            # Akka Specific
            {
                'id': 'SCALA_AKKA_UNSAFE_DISPATCHER',
                'pattern': r'system\.dispatcher|context\.dispatcher',
                'severity': 'low',
                'cwe': 'CWE-400',
                'description': 'Using default dispatcher for blocking operations',
                'recommendation': 'Use dedicated dispatcher for blocking operations',
                'category': 'performance'
            },
            {
                'id': 'SCALA_AKKA_UNHANDLED_MESSAGES',
                'pattern': r'def\s+receive\s*=\s*\{[^}]*\}(?!.*case\s+_)',
                'severity': 'low',
                'cwe': 'CWE-248',
                'description': 'Actor receive method without catch-all case',
                'recommendation': 'Handle unknown messages to prevent unhandled message warnings',
                'category': 'error_handling'
            },
            
            # Functional Programming Issues
            {
                'id': 'SCALA_UNSAFE_GET',
                'pattern': r'\.get(?!\w)|\.head(?!\w)',
                'severity': 'medium',
                'cwe': 'CWE-248',
                'description': 'Unsafe extraction from Option or collection',
                'recommendation': 'Use safe extraction methods like getOrElse or headOption',
                'category': 'error_handling'
            },
            {
                'id': 'SCALA_NULL_POINTER_RISK',
                'pattern': r'null|\.asInstanceOf\[',
                'severity': 'medium',
                'cwe': 'CWE-476',
                'description': 'Potential null pointer exception',
                'recommendation': 'Use Option types and avoid null values',
                'category': 'null_safety'
            },
            
            # Configuration Issues
            {
                'id': 'SCALA_DEBUG_MODE_ENABLED',
                'pattern': r'application\.mode\s*=\s*dev|play\.mode\s*=\s*dev',
                'severity': 'medium',
                'cwe': 'CWE-489',
                'description': 'Debug mode enabled in configuration',
                'recommendation': 'Disable debug mode in production environments',
                'category': 'configuration'
            },
            {
                'id': 'SCALA_SENSITIVE_INFO_LOGGING',
                'pattern': r'log\.[^(]*\([^)]*(?:password|secret|token|key)[^)]*\)',
                'severity': 'medium',
                'cwe': 'CWE-532',
                'description': 'Sensitive information in log statements',
                'recommendation': 'Avoid logging sensitive information',
                'category': 'information_disclosure'
            }
        ]
    
    def scan_code(self, code: str, filename: str = '') -> List[Dict[str, Any]]:
        """Scan Scala code for security vulnerabilities"""
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
                        'confidence': self._calculate_confidence(pattern_info, line, match)
                    }
                    vulnerabilities.append(vulnerability)
        
        # Add Scala-specific advanced analysis
        vulnerabilities.extend(self._advanced_scala_analysis(code, lines))
        
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
    
    def _calculate_confidence(self, pattern_info: Dict, line: str, match: re.Match) -> float:
        """Calculate confidence score for the vulnerability"""
        base_confidence = 0.8
        
        # Increase confidence for critical patterns
        if pattern_info['severity'] == 'critical':
            base_confidence = 0.95
        elif pattern_info['severity'] == 'high':
            base_confidence = 0.85
        
        # Decrease confidence if in test files
        if 'test' in line.lower() or 'spec' in line.lower():
            base_confidence *= 0.7
        
        # Increase confidence for framework-specific patterns
        if 'play' in pattern_info['id'].lower() and 'play' in line.lower():
            base_confidence = min(0.95, base_confidence + 0.1)
        
        if 'akka' in pattern_info['id'].lower() and 'akka' in line.lower():
            base_confidence = min(0.95, base_confidence + 0.1)
        
        return round(base_confidence, 2)
    
    def _advanced_scala_analysis(self, code: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Perform advanced Scala-specific security analysis"""
        vulnerabilities = []
        
        # Check for implicit conversions that might hide security issues
        implicit_pattern = r'implicit\s+def\s+\w+.*:\s*\w+\s*=>'
        for line_num, line in enumerate(lines, 1):
            if re.search(implicit_pattern, line):
                vulnerabilities.append({
                    'type': 'Potentially Unsafe Implicit Conversion',
                    'severity': 'low',
                    'line': line_num,
                    'column': 1,
                    'description': 'Implicit conversions can hide type safety issues',
                    'recommendation': 'Review implicit conversions for security implications',
                    'cwe': 'CWE-704',
                    'category': 'type_safety',
                    'code_snippet': line.strip(),
                    'pattern_id': 'SCALA_UNSAFE_IMPLICIT',
                    'confidence': 0.60
                })
        
        # Check for Future operations without proper error handling
        future_pattern = r'Future\s*\{[^}]*\}(?!\s*\.recover|\s*\.recoverWith|\s*\.onFailure)'
        for line_num, line in enumerate(lines, 1):
            if re.search(future_pattern, line):
                vulnerabilities.append({
                    'type': 'Future Without Error Handling',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'Future operations should handle potential failures',
                    'recommendation': 'Add error handling with recover, recoverWith, or onFailure',
                    'cwe': 'CWE-248',
                    'category': 'error_handling',
                    'code_snippet': line.strip(),
                    'pattern_id': 'SCALA_FUTURE_NO_ERROR_HANDLING',
                    'confidence': 0.75
                })
        
        # Check for potential resource leaks in Try blocks
        try_pattern = r'Try\s*\{[^}]*(?:FileInputStream|FileOutputStream|Socket)[^}]*\}(?!\s*\.recover|\s*\.finally)'
        for line_num, line in enumerate(lines, 1):
            if re.search(try_pattern, line):
                vulnerabilities.append({
                    'type': 'Potential Resource Leak in Try Block',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'Resources in Try blocks may not be properly closed',
                    'recommendation': 'Use try-with-resources or ensure proper resource cleanup',
                    'cwe': 'CWE-404',
                    'category': 'resource_management',
                    'code_snippet': line.strip(),
                    'pattern_id': 'SCALA_RESOURCE_LEAK_TRY',
                    'confidence': 0.70
                })
        
        # Check for potential timing attacks in authentication
        auth_pattern = r'(?:password|secret|token)\s*==\s*(?:password|secret|token)|\.equals\s*\(\s*(?:password|secret|token)'
        for line_num, line in enumerate(lines, 1):
            if re.search(auth_pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Potential Timing Attack in Authentication',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'String comparison of secrets may be vulnerable to timing attacks',
                    'recommendation': 'Use constant-time comparison for sensitive data',
                    'cwe': 'CWE-208',
                    'category': 'cryptography',
                    'code_snippet': line.strip(),
                    'pattern_id': 'SCALA_TIMING_ATTACK',
                    'confidence': 0.75
                })
        
        return vulnerabilities
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get information about Scala language support"""
        return {
            'language': 'scala',
            'version': '1.0.0',
            'patterns_count': len(self.patterns),
            'categories': list(set(p['category'] for p in self.patterns)),
            'severity_levels': list(set(p['severity'] for p in self.patterns)),
            'frameworks': ['Play Framework', 'Akka', 'Spark'],
            'description': 'Comprehensive Scala security analysis with functional programming and JVM focus'
        }

