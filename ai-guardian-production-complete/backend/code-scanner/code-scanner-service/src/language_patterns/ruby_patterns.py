"""
Ruby-specific vulnerability detection patterns for AI Guardian
"""

import re
from typing import List, Dict, Any

class RubyVulnerabilityPatterns:
    """Ruby-specific security vulnerability patterns"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Ruby vulnerability patterns"""
        return [
            # SQL Injection vulnerabilities
            {
                'id': 'ruby_sql_injection_where',
                'name': 'SQL Injection - ActiveRecord where() with String Interpolation',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'\.where\s*\(\s*["\'].*?#\{.*?\}.*?["\']',
                'description': 'SQL injection via string interpolation in ActiveRecord where clause',
                'fix_suggestion': 'Use parameterized queries: where("name = ?", params[:name])',
                'cwe': 'CWE-89'
            },
            {
                'id': 'ruby_sql_injection_find_by_sql',
                'name': 'SQL Injection - find_by_sql with String Interpolation',
                'severity': 'critical',
                'confidence': 0.95,
                'pattern': r'find_by_sql\s*\(\s*["\'].*?#\{.*?\}.*?["\']',
                'description': 'SQL injection in find_by_sql with string interpolation',
                'fix_suggestion': 'Use parameterized queries with placeholders',
                'cwe': 'CWE-89'
            },
            {
                'id': 'ruby_sql_injection_execute',
                'name': 'SQL Injection - ActiveRecord execute() with Interpolation',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'\.execute\s*\(\s*["\'].*?#\{.*?\}.*?["\']',
                'description': 'SQL injection in ActiveRecord execute method',
                'fix_suggestion': 'Use parameterized queries or sanitize input',
                'cwe': 'CWE-89'
            },
            
            # Command Injection
            {
                'id': 'ruby_command_injection_system',
                'name': 'Command Injection - system() with User Input',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'system\s*\(\s*["\'].*?#\{.*?\}.*?["\']',
                'description': 'Command injection via system() with string interpolation',
                'fix_suggestion': 'Use array form: system(["command", arg1, arg2]) or sanitize input',
                'cwe': 'CWE-78'
            },
            {
                'id': 'ruby_command_injection_backticks',
                'name': 'Command Injection - Backticks with User Input',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'`.*?#\{.*?\}.*?`',
                'description': 'Command injection via backticks with string interpolation',
                'fix_suggestion': 'Use Open3.capture3() or system() with array arguments',
                'cwe': 'CWE-78'
            },
            {
                'id': 'ruby_command_injection_exec',
                'name': 'Command Injection - exec() with User Input',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'exec\s*\(\s*["\'].*?#\{.*?\}.*?["\']',
                'description': 'Command injection via exec() with string interpolation',
                'fix_suggestion': 'Use array form or sanitize input with Shellwords.escape',
                'cwe': 'CWE-78'
            },
            
            # Code Injection / Deserialization
            {
                'id': 'ruby_code_injection_eval',
                'name': 'Code Injection - eval() with User Input',
                'severity': 'critical',
                'confidence': 0.95,
                'pattern': r'eval\s*\(\s*.*?params\[',
                'description': 'Code injection via eval() with user-controlled input',
                'fix_suggestion': 'Avoid eval() entirely or use safe alternatives like YAML.safe_load',
                'cwe': 'CWE-94'
            },
            {
                'id': 'ruby_unsafe_yaml_load',
                'name': 'Unsafe Deserialization - YAML.load()',
                'severity': 'critical',
                'confidence': 0.9,
                'pattern': r'YAML\.load\s*\(',
                'description': 'Unsafe YAML deserialization can lead to remote code execution',
                'fix_suggestion': 'Use YAML.safe_load() instead of YAML.load()',
                'cwe': 'CWE-502'
            },
            {
                'id': 'ruby_unsafe_marshal_load',
                'name': 'Unsafe Deserialization - Marshal.load()',
                'severity': 'critical',
                'confidence': 0.95,
                'pattern': r'Marshal\.load\s*\(',
                'description': 'Unsafe Marshal deserialization can lead to remote code execution',
                'fix_suggestion': 'Avoid Marshal.load() with untrusted data, use JSON instead',
                'cwe': 'CWE-502'
            },
            
            # File Operations
            {
                'id': 'ruby_path_traversal_file_read',
                'name': 'Path Traversal - File.read() with User Input',
                'severity': 'high',
                'confidence': 0.85,
                'pattern': r'File\.read\s*\(\s*.*?params\[',
                'description': 'Path traversal vulnerability in file reading',
                'fix_suggestion': 'Validate and sanitize file paths, use File.expand_path with safe directory',
                'cwe': 'CWE-22'
            },
            {
                'id': 'ruby_path_traversal_file_open',
                'name': 'Path Traversal - File.open() with User Input',
                'severity': 'high',
                'confidence': 0.85,
                'pattern': r'File\.open\s*\(\s*.*?params\[',
                'description': 'Path traversal vulnerability in file operations',
                'fix_suggestion': 'Validate file paths and restrict to safe directories',
                'cwe': 'CWE-22'
            },
            {
                'id': 'ruby_file_upload_unsafe',
                'name': 'Unsafe File Upload - Direct File Write',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'File\.write\s*\(\s*.*?params\[.*?\]\[.*?tempfile.*?\]',
                'description': 'Unsafe file upload without proper validation',
                'fix_suggestion': 'Validate file types, extensions, and content before saving',
                'cwe': 'CWE-434'
            },
            
            # Cross-Site Scripting (XSS)
            {
                'id': 'ruby_xss_raw_output',
                'name': 'XSS - raw() Output Without Sanitization',
                'severity': 'high',
                'confidence': 0.85,
                'pattern': r'raw\s*\(\s*.*?params\[',
                'description': 'XSS vulnerability via raw() output of user input',
                'fix_suggestion': 'Use html_escape() or sanitize user input before raw() output',
                'cwe': 'CWE-79'
            },
            {
                'id': 'ruby_xss_html_safe',
                'name': 'XSS - html_safe on User Input',
                'severity': 'high',
                'confidence': 0.85,
                'pattern': r'params\[.*?\]\.html_safe',
                'description': 'XSS vulnerability by marking user input as html_safe',
                'fix_suggestion': 'Sanitize user input before marking as html_safe',
                'cwe': 'CWE-79'
            },
            
            # Mass Assignment
            {
                'id': 'ruby_mass_assignment_permit_all',
                'name': 'Mass Assignment - permit! Without Restrictions',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'params\.permit!',
                'description': 'Mass assignment vulnerability by permitting all parameters',
                'fix_suggestion': 'Use strong parameters with explicit permit() list',
                'cwe': 'CWE-915'
            },
            {
                'id': 'ruby_mass_assignment_require_permit',
                'name': 'Mass Assignment - Missing Strong Parameters',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'\.create\s*\(\s*params\[(?!.*require.*permit)',
                'description': 'Potential mass assignment without strong parameters',
                'fix_suggestion': 'Use params.require().permit() to whitelist allowed attributes',
                'cwe': 'CWE-915'
            },
            
            # Authentication and Session Issues
            {
                'id': 'ruby_weak_session_secret',
                'name': 'Weak Session Secret - Hardcoded Secret',
                'severity': 'high',
                'confidence': 0.8,
                'pattern': r'config\.secret_key_base\s*=\s*["\'][a-zA-Z0-9]{10,50}["\']',
                'description': 'Hardcoded session secret key in source code',
                'fix_suggestion': 'Use environment variables or Rails credentials for secret keys',
                'cwe': 'CWE-798'
            },
            {
                'id': 'ruby_session_fixation',
                'name': 'Session Fixation - Missing reset_session',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'session\[.*?\]\s*=.*?(?!.*reset_session)',
                'description': 'Potential session fixation vulnerability',
                'fix_suggestion': 'Call reset_session before setting session variables after authentication',
                'cwe': 'CWE-384'
            },
            
            # Cryptographic Issues
            {
                'id': 'ruby_weak_random',
                'name': 'Weak Random Number Generation - rand()',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'rand\s*\(',
                'description': 'Use of weak random number generator for security purposes',
                'fix_suggestion': 'Use SecureRandom for cryptographic randomness',
                'cwe': 'CWE-338'
            },
            {
                'id': 'ruby_weak_hash_md5',
                'name': 'Weak Cryptographic Hash - MD5',
                'severity': 'medium',
                'confidence': 0.9,
                'pattern': r'Digest::MD5',
                'description': 'Use of cryptographically weak MD5 hash function',
                'fix_suggestion': 'Use Digest::SHA256 or bcrypt for password hashing',
                'cwe': 'CWE-327'
            },
            {
                'id': 'ruby_weak_hash_sha1',
                'name': 'Weak Cryptographic Hash - SHA1',
                'severity': 'medium',
                'confidence': 0.85,
                'pattern': r'Digest::SHA1',
                'description': 'Use of cryptographically weak SHA1 hash function',
                'fix_suggestion': 'Use Digest::SHA256 or stronger hash functions',
                'cwe': 'CWE-327'
            },
            
            # Regular Expression DoS
            {
                'id': 'ruby_regex_dos',
                'name': 'Regular Expression DoS - Complex Regex with User Input',
                'severity': 'medium',
                'confidence': 0.7,
                'pattern': r'\/.*?\+.*?\*.*?\/\.match\s*\(\s*.*?params\[',
                'description': 'Potential ReDoS vulnerability with complex regex on user input',
                'fix_suggestion': 'Simplify regex patterns or validate input length',
                'cwe': 'CWE-1333'
            },
            
            # Information Disclosure
            {
                'id': 'ruby_debug_info_disclosure',
                'name': 'Information Disclosure - Debug Information',
                'severity': 'low',
                'confidence': 0.8,
                'pattern': r'puts\s+.*?\.inspect',
                'description': 'Debug information disclosure via puts inspect',
                'fix_suggestion': 'Remove debug statements from production code',
                'cwe': 'CWE-209'
            },
            {
                'id': 'ruby_exception_disclosure',
                'name': 'Information Disclosure - Exception Details',
                'severity': 'low',
                'confidence': 0.7,
                'pattern': r'rescue.*?=>.*?render.*?text.*?\.message',
                'description': 'Exception details exposed to users',
                'fix_suggestion': 'Log errors securely and show generic error messages to users',
                'cwe': 'CWE-209'
            },
            
            # CSRF Protection
            {
                'id': 'ruby_csrf_skip_verification',
                'name': 'CSRF Protection Disabled - skip_before_action',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'skip_before_action\s+:verify_authenticity_token',
                'description': 'CSRF protection disabled for controller actions',
                'fix_suggestion': 'Enable CSRF protection or use specific action exemptions carefully',
                'cwe': 'CWE-352'
            },
            
            # Open Redirect
            {
                'id': 'ruby_open_redirect',
                'name': 'Open Redirect - redirect_to with User Input',
                'severity': 'medium',
                'confidence': 0.8,
                'pattern': r'redirect_to\s+.*?params\[',
                'description': 'Open redirect vulnerability via user-controlled URL',
                'fix_suggestion': 'Validate redirect URLs against whitelist of allowed domains',
                'cwe': 'CWE-601'
            },
            
            # SSL/TLS Issues
            {
                'id': 'ruby_ssl_verification_disabled',
                'name': 'SSL Verification Disabled - verify_mode NONE',
                'severity': 'high',
                'confidence': 0.9,
                'pattern': r'verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE',
                'description': 'SSL certificate verification disabled',
                'fix_suggestion': 'Enable SSL verification: OpenSSL::SSL::VERIFY_PEER',
                'cwe': 'CWE-295'
            }
        ]
    
    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """Scan Ruby code for vulnerabilities"""
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
        """Get supported file extensions for Ruby"""
        return ['.rb', '.rbw', '.rake', '.gemspec']
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get Ruby language information"""
        return {
            'name': 'Ruby',
            'version': '3.x',
            'extensions': self.get_supported_extensions(),
            'pattern_count': len(self.patterns),
            'categories': [
                'SQL Injection',
                'Command Injection',
                'Code Injection',
                'Unsafe Deserialization',
                'Path Traversal',
                'Cross-Site Scripting (XSS)',
                'Mass Assignment',
                'Authentication Issues',
                'Cryptographic Issues',
                'Regular Expression DoS',
                'Information Disclosure',
                'CSRF Protection',
                'Open Redirect',
                'SSL/TLS Issues'
            ]
        }

