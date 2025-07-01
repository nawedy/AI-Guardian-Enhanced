"""
PHP-specific vulnerability detection patterns for AI Guardian
"""

import re
from typing import List, Dict, Any

class PHPVulnerabilityPatterns:
    """PHP-specific security vulnerability patterns"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize PHP vulnerability patterns"""
        return [
            # SQL Injection vulnerabilities
            {
                'id': 'php_sql_injection_mysql',
                'name': 'SQL Injection - MySQL Query',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'mysql_query\s*\(\s*["\'].*?\$.*?["\']',
                'description': 'Direct variable interpolation in MySQL query without sanitization',
                'fix_suggestion': 'Use prepared statements with PDO or mysqli_prepare()',
                'cwe': 'CWE-89'
            },
            {
                'id': 'php_sql_injection_pdo_concat',
                'name': 'SQL Injection - PDO String Concatenation',
                'severity': 'critical',
                'confidence': 0.85,
                'pattern': r'\$pdo->query\s*\(\s*["\'].*?\.\s*\$.*?["\']',
                'description': 'SQL query with string concatenation in PDO',
                'fix_suggestion': 'Use PDO prepared statements with parameter binding',
                'cwe': 'CWE-89'
            },
            
            # Cross-Site Scripting (XSS)
            {
                'id': 'php_xss_echo_get',
                'name': 'XSS - Direct Echo of GET Parameter',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'echo\s+\$_GET\[',
                'description': 'Direct output of GET parameter without sanitization',
                'fix_suggestion': 'Use htmlspecialchars() or filter_input() to sanitize output',
                'cwe': 'CWE-79'
            },
            {
                'id': 'php_xss_echo_post',
                'name': 'XSS - Direct Echo of POST Parameter',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'echo\s+\$_POST\[',
                'description': 'Direct output of POST parameter without sanitization',
                'fix_suggestion': 'Use htmlspecialchars() or filter_input() to sanitize output',
                'cwe': 'CWE-79'
            },
            {
                'id': 'php_xss_print_request',
                'name': 'XSS - Direct Print of Request Data',
                'severity': 'high',
                'confidence': 0.85,
                'pattern': r'print\s+\$_REQUEST\[',
                'description': 'Direct output of REQUEST parameter without sanitization',
                'fix_suggestion': 'Use htmlspecialchars() to escape output',
                'cwe': 'CWE-79'
            },
            
            # File Inclusion vulnerabilities
            {
                'id': 'php_lfi_include_get',
                'name': 'Local File Inclusion - Include with GET',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'include\s*\(\s*\$_GET\[',
                'description': 'File inclusion using unvalidated GET parameter',
                'fix_suggestion': 'Validate and whitelist allowed files before inclusion',
                'cwe': 'CWE-98'
            },
            {
                'id': 'php_rfi_include_url',
                'name': 'Remote File Inclusion - Include URL',
                'severity': 'critical',
                'confidence': 0.95,
                'pattern': r'include\s*\(\s*["\']https?://',
                'description': 'Remote file inclusion from external URL',
                'fix_suggestion': 'Disable allow_url_include and validate file paths',
                'cwe': 'CWE-98'
            },
            {
                'id': 'php_lfi_require_post',
                'name': 'Local File Inclusion - Require with POST',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'require\s*\(\s*\$_POST\[',
                'description': 'File inclusion using unvalidated POST parameter',
                'fix_suggestion': 'Validate and whitelist allowed files before inclusion',
                'cwe': 'CWE-98'
            },
            
            # Command Injection
            {
                'id': 'php_command_injection_exec',
                'name': 'Command Injection - exec() with User Input',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'exec\s*\(\s*.*?\$_(GET|POST|REQUEST)\[',
                'description': 'Command execution with unvalidated user input',
                'fix_suggestion': 'Use escapeshellarg() or avoid system commands entirely',
                'cwe': 'CWE-78'
            },
            {
                'id': 'php_command_injection_system',
                'name': 'Command Injection - system() with User Input',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'system\s*\(\s*.*?\$_(GET|POST|REQUEST)\[',
                'description': 'System command execution with unvalidated user input',
                'fix_suggestion': 'Use escapeshellarg() or avoid system commands entirely',
                'cwe': 'CWE-78'
            },
            {
                'id': 'php_command_injection_shell_exec',
                'name': 'Command Injection - shell_exec() with User Input',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'shell_exec\s*\(\s*.*?\$_(GET|POST|REQUEST)\[',
                'description': 'Shell command execution with unvalidated user input',
                'fix_suggestion': 'Use escapeshellarg() or avoid shell commands entirely',
                'cwe': 'CWE-78'
            },
            
            # Deserialization vulnerabilities
            {
                'id': 'php_unsafe_unserialize',
                'name': 'Unsafe Deserialization - unserialize() with User Input',
                'severity': 'critical',
                'confidence': 0.85,
                'pattern': r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[',
                'description': 'Unsafe deserialization of user-controlled data',
                'fix_suggestion': 'Validate data before deserialization or use JSON instead',
                'cwe': 'CWE-502'
            },
            
            # File Upload vulnerabilities
            {
                'id': 'php_unsafe_file_upload',
                'name': 'Unsafe File Upload - No Extension Validation',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'move_uploaded_file\s*\(\s*\$_FILES\[.*?\]\[[\'"]+tmp_name[\'"]+\]',
                'description': 'File upload without proper extension or content validation',
                'fix_suggestion': 'Validate file extensions, MIME types, and scan for malicious content',
                'cwe': 'CWE-434'
            },
            
            # Session vulnerabilities
            {
                'id': 'php_session_fixation',
                'name': 'Session Fixation - Missing session_regenerate_id()',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'session_start\s*\(\s*\)(?!.*session_regenerate_id)',
                'description': 'Session started without regenerating session ID',
                'fix_suggestion': 'Call session_regenerate_id() after authentication',
                'cwe': 'CWE-384'
            },
            
            # Cryptographic issues
            {
                'id': 'php_weak_random',
                'name': 'Weak Random Number Generation - rand()',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'rand\s*\(\s*\)',
                'description': 'Use of weak random number generator for security purposes',
                'fix_suggestion': 'Use random_int() or random_bytes() for cryptographic randomness',
                'cwe': 'CWE-338'
            },
            {
                'id': 'php_weak_hash_md5',
                'name': 'Weak Cryptographic Hash - MD5',
                'severity': 'medium',
                'confidence': 0.9,
                'pattern': r'md5\s*\(',
                'description': 'Use of cryptographically weak MD5 hash function',
                'fix_suggestion': 'Use password_hash() for passwords or hash() with SHA-256',
                'cwe': 'CWE-327'
            },
            {
                'id': 'php_weak_hash_sha1',
                'name': 'Weak Cryptographic Hash - SHA1',
                'severity': 'medium',
                'confidence': 0.85,
                'pattern': r'sha1\s*\(',
                'description': 'Use of cryptographically weak SHA1 hash function',
                'fix_suggestion': 'Use password_hash() for passwords or hash() with SHA-256',
                'cwe': 'CWE-327'
            },
            
            # Information disclosure
            {
                'id': 'php_error_disclosure',
                'name': 'Information Disclosure - Error Display Enabled',
                'severity': 'low',
                'confidence': 0.9,
                'pattern': r'ini_set\s*\(\s*["\']display_errors["\'],\s*["\']?1["\']?\s*\)',
                'description': 'Error display enabled in production code',
                'fix_suggestion': 'Disable error display in production and log errors instead',
                'cwe': 'CWE-209'
            },
            {
                'id': 'php_phpinfo_disclosure',
                'name': 'Information Disclosure - phpinfo() Call',
                'severity': 'medium',
                'confidence': 0.95,
                'pattern': r'phpinfo\s*\(\s*\)',
                'description': 'phpinfo() call can reveal sensitive server information',
                'fix_suggestion': 'Remove phpinfo() calls from production code',
                'cwe': 'CWE-209'
            },
            
            # LDAP Injection
            {
                'id': 'php_ldap_injection',
                'name': 'LDAP Injection - Unescaped User Input',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'ldap_search\s*\([^)]*\$_(GET|POST|REQUEST)\[',
                'description': 'LDAP search with unescaped user input',
                'fix_suggestion': 'Escape LDAP special characters in user input',
                'cwe': 'CWE-90'
            },
            
            # XML vulnerabilities
            {
                'id': 'php_xxe_vulnerability',
                'name': 'XXE - XML External Entity Processing',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'simplexml_load_string\s*\(\s*\$_(GET|POST|REQUEST)\[',
                'description': 'XML parsing with potential XXE vulnerability',
                'fix_suggestion': 'Disable external entity loading in XML parser',
                'cwe': 'CWE-611'
            },
            
            # Path traversal
            {
                'id': 'php_path_traversal',
                'name': 'Path Traversal - Directory Traversal Attack',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'(file_get_contents|fopen|readfile)\s*\(\s*.*?\$_(GET|POST|REQUEST)\[',
                'description': 'File operations with unvalidated user input',
                'fix_suggestion': 'Validate and sanitize file paths, use basename()',
                'cwe': 'CWE-22'
            }
        ]
    
    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """Scan PHP code for vulnerabilities"""
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
        """Get supported file extensions for PHP"""
        return ['.php', '.phtml', '.php3', '.php4', '.php5', '.phps']
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get PHP language information"""
        return {
            'name': 'PHP',
            'version': '8.x',
            'extensions': self.get_supported_extensions(),
            'pattern_count': len(self.patterns),
            'categories': [
                'SQL Injection',
                'Cross-Site Scripting (XSS)',
                'File Inclusion',
                'Command Injection',
                'Deserialization',
                'File Upload',
                'Session Management',
                'Cryptographic Issues',
                'Information Disclosure',
                'LDAP Injection',
                'XML External Entity (XXE)',
                'Path Traversal'
            ]
        }

