"""
TypeScript Security Patterns for AI Guardian
Enhanced JavaScript security analysis with TypeScript type safety features
"""

import re
from typing import List, Dict, Any

class TypeScriptSecurityPatterns:
    """TypeScript-specific security vulnerability patterns"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize TypeScript security patterns"""
        return [
            # Type Safety Issues
            {
                'id': 'TS_ANY_TYPE_USAGE',
                'name': 'Any Type Usage',
                'pattern': r':\s*any\b|as\s+any\b|<any>',
                'severity': 'medium',
                'cwe': 'CWE-704',
                'description': 'Use of any type bypasses TypeScript type checking',
                'recommendation': 'Use specific types or unknown type for better type safety',
                'category': 'type_safety'
            },
            {
                'id': 'TS_TYPE_ASSERTION_UNSAFE',
                'name': 'Unsafe Type Assertion',
                'pattern': r'as\s+\w+(?!\s*\||\s*&)|<\w+>(?!\s*\()',
                'severity': 'medium',
                'cwe': 'CWE-704',
                'description': 'Type assertion without runtime validation',
                'recommendation': 'Add runtime type checking or use type guards',
                'category': 'type_safety'
            },
            {
                'id': 'TS_NON_NULL_ASSERTION',
                'name': 'Non-null Assertion Operator',
                'pattern': r'!\s*(?:\.|$|\[)',
                'severity': 'medium',
                'cwe': 'CWE-476',
                'description': 'Non-null assertion operator bypasses null safety',
                'recommendation': 'Use optional chaining or proper null checks',
                'category': 'null_safety'
            },
            
            # Injection Vulnerabilities
            {
                'id': 'TS_SQL_INJECTION',
                'name': 'SQL Injection',
                'pattern': r'query\s*\(\s*[`"\'].*\$\{.*\}.*[`"\']\s*\)|execute\s*\(\s*[`"\'].*\$\{.*\}.*[`"\']\s*\)',
                'severity': 'critical',
                'cwe': 'CWE-89',
                'description': 'SQL query with template literal interpolation',
                'recommendation': 'Use parameterized queries or prepared statements',
                'category': 'injection'
            },
            {
                'id': 'TS_NOSQL_INJECTION',
                'name': 'NoSQL Injection',
                'pattern': r'find\s*\(\s*\{[^}]*\$\{.*\}[^}]*\}\s*\)|findOne\s*\(\s*\{[^}]*\$\{.*\}[^}]*\}\s*\)',
                'severity': 'critical',
                'cwe': 'CWE-943',
                'description': 'NoSQL query with dynamic content may be vulnerable to injection',
                'recommendation': 'Use parameterized queries and input validation',
                'category': 'injection'
            },
            {
                'id': 'TS_COMMAND_INJECTION',
                'name': 'Command Injection',
                'pattern': r'exec\s*\(\s*[`"\'].*\$\{.*\}.*[`"\']\s*\)|spawn\s*\(\s*[`"\'].*\$\{.*\}.*[`"\']\s*\)',
                'severity': 'critical',
                'cwe': 'CWE-78',
                'description': 'Command execution with user input',
                'recommendation': 'Use parameterized command execution and input validation',
                'category': 'injection'
            },
            
            # XSS Vulnerabilities
            {
                'id': 'TS_DOM_XSS',
                'name': 'DOM-based XSS',
                'pattern': r'innerHTML\s*=\s*.*\$\{|outerHTML\s*=\s*.*\$\{|document\.write\s*\(\s*.*\$\{',
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'Dynamic HTML content may be vulnerable to XSS',
                'recommendation': 'Use textContent or proper HTML sanitization',
                'category': 'xss'
            },
            {
                'id': 'TS_REACT_DANGEROUS_HTML',
                'name': 'React Dangerous HTML',
                'pattern': r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*.*\$\{',
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'React dangerouslySetInnerHTML with dynamic content',
                'recommendation': 'Sanitize HTML content or use safe alternatives',
                'category': 'xss'
            },
            {
                'id': 'TS_ANGULAR_BYPASS_SANITIZATION',
                'name': 'Angular Sanitization Bypass',
                'pattern': r'bypassSecurityTrust\w+\s*\(\s*.*\$\{',
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'Angular sanitization bypass with dynamic content',
                'recommendation': 'Avoid bypassing sanitization or ensure content is safe',
                'category': 'xss'
            },
            
            # Authentication and Authorization
            {
                'id': 'TS_HARDCODED_CREDENTIALS',
                'name': 'Hardcoded Credentials',
                'pattern': r'(?:password|secret|apikey|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
                'severity': 'critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded credentials in source code',
                'recommendation': 'Use environment variables or secure configuration',
                'category': 'authentication'
            },
            {
                'id': 'TS_JWT_NO_VERIFICATION',
                'name': 'JWT Without Verification',
                'pattern': r'jwt\.decode\s*\([^)]*\)(?!\s*,\s*[^,)]+)|jsonwebtoken\.decode\s*\([^)]*\)(?!\s*,\s*[^,)]+)',
                'severity': 'high',
                'cwe': 'CWE-347',
                'description': 'JWT token decoded without signature verification',
                'recommendation': 'Use jwt.verify() to validate token signatures',
                'category': 'authentication'
            },
            {
                'id': 'TS_WEAK_SESSION_CONFIG',
                'name': 'Weak Session Configuration',
                'pattern': r'session\s*\(\s*\{[^}]*secure\s*:\s*false[^}]*\}|session\s*\(\s*\{[^}]*httpOnly\s*:\s*false[^}]*\}',
                'severity': 'medium',
                'cwe': 'CWE-614',
                'description': 'Session configuration with security flags disabled',
                'recommendation': 'Enable secure and httpOnly flags for session cookies',
                'category': 'session_management'
            },
            
            # Cryptographic Issues
            {
                'id': 'TS_WEAK_CRYPTO',
                'name': 'Weak Cryptographic Algorithm',
                'pattern': r'createHash\s*\(\s*["\'](?:md5|sha1)["\']|createCipher\s*\(\s*["\'](?:des|rc4)["\']',
                'severity': 'high',
                'cwe': 'CWE-327',
                'description': 'Use of weak cryptographic algorithms',
                'recommendation': 'Use strong algorithms like SHA-256, AES',
                'category': 'cryptography'
            },
            {
                'id': 'TS_CRYPTO_RANDOM_WEAK',
                'name': 'Weak Random Number Generation',
                'pattern': r'Math\.random\(\)(?!\s*\*\s*Math\.floor)',
                'severity': 'medium',
                'cwe': 'CWE-338',
                'description': 'Math.random() is not cryptographically secure',
                'recommendation': 'Use crypto.randomBytes() for cryptographic operations',
                'category': 'cryptography'
            },
            {
                'id': 'TS_HARDCODED_CRYPTO_KEY',
                'name': 'Hardcoded Cryptographic Key',
                'pattern': r'(?:key|secret|iv)\s*[:=]\s*["\'][a-fA-F0-9]{16,}["\']',
                'severity': 'critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded cryptographic key or IV',
                'recommendation': 'Generate keys dynamically or load from secure storage',
                'category': 'cryptography'
            },
            
            # Input Validation
            {
                'id': 'TS_REGEX_INJECTION',
                'name': 'Regular Expression Injection',
                'pattern': r'new\s+RegExp\s*\(\s*.*\$\{.*\}\s*\)|RegExp\s*\(\s*.*\$\{.*\}\s*\)',
                'severity': 'medium',
                'cwe': 'CWE-20',
                'description': 'Regular expression with user input may cause ReDoS',
                'recommendation': 'Validate and sanitize regex patterns',
                'category': 'input_validation'
            },
            {
                'id': 'TS_PATH_TRAVERSAL',
                'name': 'Path Traversal',
                'pattern': r'(?:readFile|writeFile|createReadStream)\s*\(\s*.*\.\.[^)]*\)|path\.join\s*\([^)]*\.\.[^)]*\)',
                'severity': 'high',
                'cwe': 'CWE-22',
                'description': 'File operations with potential path traversal',
                'recommendation': 'Validate and sanitize file paths',
                'category': 'path_traversal'
            },
            {
                'id': 'TS_PROTOTYPE_POLLUTION',
                'name': 'Prototype Pollution',
                'pattern': r'JSON\.parse\s*\([^)]*\)(?!\s*,\s*reviver)|Object\.assign\s*\(\s*\{\}\s*,\s*.*\$\{',
                'severity': 'high',
                'cwe': 'CWE-1321',
                'description': 'Potential prototype pollution vulnerability',
                'recommendation': 'Use Object.create(null) or validate object properties',
                'category': 'prototype_pollution'
            },
            
            # Network Security
            {
                'id': 'TS_INSECURE_HTTP',
                'name': 'Insecure HTTP Communication',
                'pattern': r'http://[^"\s]+|fetch\s*\(\s*["\']http:[^"\']+["\']',
                'severity': 'medium',
                'cwe': 'CWE-319',
                'description': 'Insecure HTTP communication',
                'recommendation': 'Use HTTPS for all network communications',
                'category': 'network_security'
            },
            {
                'id': 'TS_CORS_WILDCARD',
                'name': 'CORS Wildcard Origin',
                'pattern': r'Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*["\']?',
                'severity': 'medium',
                'cwe': 'CWE-346',
                'description': 'CORS configured with wildcard origin',
                'recommendation': 'Use specific origins instead of wildcard',
                'category': 'cors'
            },
            {
                'id': 'TS_TLS_REJECT_UNAUTHORIZED',
                'name': 'TLS Certificate Validation Disabled',
                'pattern': r'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0["\']',
                'severity': 'critical',
                'cwe': 'CWE-295',
                'description': 'TLS certificate validation is disabled',
                'recommendation': 'Enable proper TLS certificate validation',
                'category': 'network_security'
            },
            
            # Express.js Specific
            {
                'id': 'TS_EXPRESS_TRUST_PROXY',
                'name': 'Express Trust Proxy Misconfiguration',
                'pattern': r'app\.set\s*\(\s*["\']trust\s+proxy["\'],\s*true\s*\)',
                'severity': 'medium',
                'cwe': 'CWE-16',
                'description': 'Express trust proxy set to true without proper configuration',
                'recommendation': 'Configure trust proxy with specific values',
                'category': 'express_security'
            },
            {
                'id': 'TS_EXPRESS_NO_HELMET',
                'name': 'Missing Security Headers',
                'pattern': r'express\(\)(?!.*helmet)',
                'severity': 'medium',
                'cwe': 'CWE-693',
                'description': 'Express app without security headers middleware',
                'recommendation': 'Use helmet.js for security headers',
                'category': 'express_security'
            },
            
            # React/Angular Specific
            {
                'id': 'TS_REACT_UNSAFE_REFS',
                'name': 'React Unsafe Ref Usage',
                'pattern': r'ref\s*=\s*\{.*\$\{.*\}\}|createRef\s*\(\s*.*\$\{.*\}\s*\)',
                'severity': 'medium',
                'cwe': 'CWE-79',
                'description': 'React ref with dynamic content',
                'recommendation': 'Use static refs or validate dynamic content',
                'category': 'react_security'
            },
            {
                'id': 'TS_ANGULAR_TEMPLATE_INJECTION',
                'name': 'Angular Template Injection',
                'pattern': r'\{\{.*\$\{.*\}\}\}|\[innerHTML\]\s*=\s*.*\$\{',
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'Angular template with dynamic content injection',
                'recommendation': 'Use Angular\'s built-in sanitization',
                'category': 'angular_security'
            },
            
            # Node.js Specific
            {
                'id': 'TS_NODE_EVAL_USAGE',
                'name': 'Eval Usage',
                'pattern': r'eval\s*\(|Function\s*\(\s*.*\$\{.*\}\s*\)',
                'severity': 'critical',
                'cwe': 'CWE-95',
                'description': 'Use of eval() or Function constructor with dynamic content',
                'recommendation': 'Avoid eval() or use safer alternatives like JSON.parse()',
                'category': 'code_injection'
            },
            {
                'id': 'TS_NODE_CHILD_PROCESS',
                'name': 'Unsafe Child Process',
                'pattern': r'child_process\.exec\s*\(\s*.*\$\{.*\}\s*\)',
                'severity': 'critical',
                'cwe': 'CWE-78',
                'description': 'Child process execution with user input',
                'recommendation': 'Use execFile() or spawn() with argument arrays',
                'category': 'command_injection'
            },
            
            # Error Handling
            {
                'id': 'TS_SENSITIVE_ERROR_EXPOSURE',
                'name': 'Sensitive Information in Error Messages',
                'pattern': r'throw\s+new\s+Error\s*\(\s*.*(?:password|secret|token|key).*\)|console\.error\s*\(\s*.*(?:password|secret|token|key).*\)',
                'severity': 'medium',
                'cwe': 'CWE-209',
                'description': 'Sensitive information exposed in error messages',
                'recommendation': 'Avoid exposing sensitive data in error messages',
                'category': 'information_disclosure'
            },
            {
                'id': 'TS_UNHANDLED_PROMISE_REJECTION',
                'name': 'Unhandled Promise Rejection',
                'pattern': r'new\s+Promise\s*\([^)]*\)(?!\s*\.catch|\s*\.then\([^)]*,)',
                'severity': 'low',
                'cwe': 'CWE-248',
                'description': 'Promise without error handling',
                'recommendation': 'Add .catch() or try-catch for async/await',
                'category': 'error_handling'
            },
            
            # File System Security
            {
                'id': 'TS_INSECURE_FILE_UPLOAD',
                'name': 'Insecure File Upload',
                'pattern': r'multer\s*\(\s*\{[^}]*dest\s*:[^}]*\}(?![^}]*fileFilter)',
                'severity': 'high',
                'cwe': 'CWE-434',
                'description': 'File upload without proper validation',
                'recommendation': 'Add file type validation and size limits',
                'category': 'file_upload'
            },
            
            # Database Security
            {
                'id': 'TS_MONGODB_INJECTION',
                'name': 'MongoDB Injection',
                'pattern': r'db\.collection\s*\([^)]*\)\.find\s*\(\s*\{[^}]*\$where[^}]*\}',
                'severity': 'high',
                'cwe': 'CWE-943',
                'description': 'MongoDB $where operator can execute arbitrary JavaScript',
                'recommendation': 'Avoid $where operator or use strict validation',
                'category': 'nosql_injection'
            },
            
            # Configuration Issues
            {
                'id': 'TS_DEBUG_MODE_PRODUCTION',
                'name': 'Debug Mode in Production',
                'pattern': r'NODE_ENV\s*!==\s*["\']production["\'].*console\.|process\.env\.NODE_ENV.*debug',
                'severity': 'low',
                'cwe': 'CWE-489',
                'description': 'Debug code may be present in production',
                'recommendation': 'Remove debug code from production builds',
                'category': 'debug_info'
            }
        ]
    
    def scan_code(self, code: str, filename: str = '') -> List[Dict[str, Any]]:
        """Scan TypeScript code for security vulnerabilities"""
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
        
        # Add TypeScript-specific advanced analysis
        vulnerabilities.extend(self._advanced_typescript_analysis(code, lines, filename))
        
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
        if any(test_indicator in filename.lower() for test_indicator in ['test', 'spec', '__tests__']):
            base_confidence *= 0.6
        
        # Increase confidence for framework-specific patterns
        framework_indicators = {
            'react': ['jsx', 'tsx', 'react'],
            'angular': ['component.ts', 'service.ts', 'angular'],
            'express': ['express', 'server.ts'],
            'node': ['node', 'server']
        }
        
        for framework, indicators in framework_indicators.items():
            if framework in pattern_info['id'].lower():
                if any(indicator in filename.lower() or indicator in line.lower() for indicator in indicators):
                    base_confidence = min(0.95, base_confidence + 0.1)
        
        # Increase confidence for TypeScript-specific type issues
        if pattern_info['category'] == 'type_safety' and filename.endswith('.ts'):
            base_confidence = min(0.90, base_confidence + 0.05)
        
        return round(base_confidence, 2)
    
    def _advanced_typescript_analysis(self, code: str, lines: List[str], filename: str) -> List[Dict[str, Any]]:
        """Perform advanced TypeScript-specific security analysis"""
        vulnerabilities = []
        
        # Check for missing strict mode in TypeScript config
        if 'tsconfig.json' in filename:
            strict_pattern = r'"strict"\s*:\s*false|"noImplicitAny"\s*:\s*false'
            for line_num, line in enumerate(lines, 1):
                if re.search(strict_pattern, line):
                    vulnerabilities.append({
                        'type': 'TypeScript Strict Mode Disabled',
                        'severity': 'medium',
                        'line': line_num,
                        'column': 1,
                        'description': 'TypeScript strict mode is disabled, reducing type safety',
                        'recommendation': 'Enable strict mode for better type safety',
                        'cwe': 'CWE-704',
                        'category': 'configuration',
                        'code_snippet': line.strip(),
                        'pattern_id': 'TS_STRICT_MODE_DISABLED',
                        'confidence': 0.90
                    })
        
        # Check for potential type confusion in union types
        union_type_pattern = r':\s*\w+\s*\|\s*any\b|:\s*any\s*\|\s*\w+'
        for line_num, line in enumerate(lines, 1):
            if re.search(union_type_pattern, line):
                vulnerabilities.append({
                    'type': 'Union Type with Any',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'Union type including any defeats type safety',
                    'recommendation': 'Use specific types instead of any in union types',
                    'cwe': 'CWE-704',
                    'category': 'type_safety',
                    'code_snippet': line.strip(),
                    'pattern_id': 'TS_UNION_TYPE_ANY',
                    'confidence': 0.80
                })
        
        # Check for potential security issues in decorators
        decorator_pattern = r'@\w+\s*\([^)]*\$\{.*\}[^)]*\)'
        for line_num, line in enumerate(lines, 1):
            if re.search(decorator_pattern, line):
                vulnerabilities.append({
                    'type': 'Dynamic Content in Decorator',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'Decorator with dynamic content may be unsafe',
                    'recommendation': 'Use static values in decorators',
                    'cwe': 'CWE-95',
                    'category': 'code_injection',
                    'code_snippet': line.strip(),
                    'pattern_id': 'TS_DYNAMIC_DECORATOR',
                    'confidence': 0.75
                })
        
        # Check for potential issues with module resolution
        dynamic_import_pattern = r'import\s*\(\s*.*\$\{.*\}\s*\)'
        for line_num, line in enumerate(lines, 1):
            if re.search(dynamic_import_pattern, line):
                vulnerabilities.append({
                    'type': 'Dynamic Module Import',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'Dynamic import with user input may load malicious modules',
                    'recommendation': 'Validate module paths or use static imports',
                    'cwe': 'CWE-829',
                    'category': 'module_security',
                    'code_snippet': line.strip(),
                    'pattern_id': 'TS_DYNAMIC_IMPORT',
                    'confidence': 0.80
                })
        
        # Check for potential timing attacks in string comparison
        timing_attack_pattern = r'(?:password|secret|token|hash)\s*===?\s*(?:password|secret|token|hash)|\.localeCompare\s*\(\s*(?:password|secret|token)'
        for line_num, line in enumerate(lines, 1):
            if re.search(timing_attack_pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Potential Timing Attack',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'String comparison of secrets may be vulnerable to timing attacks',
                    'recommendation': 'Use constant-time comparison for sensitive data',
                    'cwe': 'CWE-208',
                    'category': 'cryptography',
                    'code_snippet': line.strip(),
                    'pattern_id': 'TS_TIMING_ATTACK',
                    'confidence': 0.75
                })
        
        return vulnerabilities
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get information about TypeScript language support"""
        return {
            'language': 'typescript',
            'version': '1.0.0',
            'patterns_count': len(self.patterns),
            'categories': list(set(p['category'] for p in self.patterns)),
            'severity_levels': list(set(p['severity'] for p in self.patterns)),
            'frameworks': ['React', 'Angular', 'Express.js', 'Node.js', 'Vue.js'],
            'description': 'Comprehensive TypeScript security analysis with enhanced JavaScript patterns and type safety focus'
        }

