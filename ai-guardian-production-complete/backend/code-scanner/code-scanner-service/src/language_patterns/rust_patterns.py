"""
Rust Security Patterns for AI Guardian
Advanced memory safety and security analysis for Rust applications
"""

import re
from typing import List, Dict, Any

class RustSecurityPatterns:
    """Rust-specific security vulnerability patterns"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Rust security patterns"""
        return [
            # Memory Safety Violations
            {
                'id': 'RUST_UNSAFE_BLOCK',
                'name': 'Unsafe Block Usage',
                'pattern': r'unsafe\s*\{[^}]*\}',
                'severity': 'high',
                'cwe': 'CWE-119',
                'description': 'Unsafe block bypasses Rust\'s memory safety guarantees',
                'recommendation': 'Minimize unsafe code usage and ensure proper safety invariants',
                'category': 'memory_safety'
            },
            {
                'id': 'RUST_RAW_POINTER_DEREF',
                'pattern': r'\*\s*(?:const|mut)\s+\w+',
                'severity': 'high',
                'cwe': 'CWE-476',
                'description': 'Raw pointer dereference without safety checks',
                'recommendation': 'Use safe Rust alternatives or add proper null checks',
                'category': 'memory_safety'
            },
            {
                'id': 'RUST_TRANSMUTE_USAGE',
                'pattern': r'std::mem::transmute|mem::transmute',
                'severity': 'critical',
                'cwe': 'CWE-704',
                'description': 'Unsafe memory transmutation can lead to undefined behavior',
                'recommendation': 'Use safe casting methods or avoid transmute entirely',
                'category': 'memory_safety'
            },
            {
                'id': 'RUST_UNINITIALIZED_MEM',
                'pattern': r'std::mem::uninitialized|mem::uninitialized|MaybeUninit::uninit\(\)\.assume_init\(\)',
                'severity': 'critical',
                'cwe': 'CWE-908',
                'description': 'Use of uninitialized memory can cause undefined behavior',
                'recommendation': 'Use MaybeUninit properly or initialize memory before use',
                'category': 'memory_safety'
            },
            
            # Concurrency Issues
            {
                'id': 'RUST_DATA_RACE',
                'pattern': r'Arc<(?!Mutex|RwLock)\w+>',
                'severity': 'high',
                'cwe': 'CWE-362',
                'description': 'Shared mutable state without synchronization can cause data races',
                'recommendation': 'Use Mutex, RwLock, or atomic types for shared mutable data',
                'category': 'concurrency'
            },
            {
                'id': 'RUST_DEADLOCK_RISK',
                'pattern': r'\.lock\(\)\.unwrap\(\).*\.lock\(\)\.unwrap\(\)',
                'severity': 'medium',
                'cwe': 'CWE-833',
                'description': 'Multiple lock acquisitions can lead to deadlocks',
                'recommendation': 'Use consistent lock ordering or consider lock-free alternatives',
                'category': 'concurrency'
            },
            {
                'id': 'RUST_CHANNEL_PANIC',
                'pattern': r'\.recv\(\)\.unwrap\(\)|\.send\(\w+\)\.unwrap\(\)',
                'severity': 'medium',
                'cwe': 'CWE-248',
                'description': 'Channel operations can panic if the other end is disconnected',
                'recommendation': 'Handle channel errors gracefully instead of unwrapping',
                'category': 'error_handling'
            },
            
            # Cryptographic Issues
            {
                'id': 'RUST_WEAK_RANDOM',
                'pattern': r'rand::random\(\)|thread_rng\(\)\.gen\(\)',
                'severity': 'medium',
                'cwe': 'CWE-338',
                'description': 'Standard random number generator may not be cryptographically secure',
                'recommendation': 'Use OsRng or other cryptographically secure random generators',
                'category': 'cryptography'
            },
            {
                'id': 'RUST_HARDCODED_CRYPTO_KEY',
                'pattern': r'(?:key|secret|password)\s*=\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
                'severity': 'critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded cryptographic key or secret',
                'recommendation': 'Load keys from environment variables or secure key management',
                'category': 'cryptography'
            },
            {
                'id': 'RUST_WEAK_HASH',
                'pattern': r'use\s+md5|use\s+sha1|Md5::new\(\)|Sha1::new\(\)',
                'severity': 'high',
                'cwe': 'CWE-327',
                'description': 'Use of weak cryptographic hash functions',
                'recommendation': 'Use SHA-256, SHA-3, or other secure hash functions',
                'category': 'cryptography'
            },
            
            # Input Validation
            {
                'id': 'RUST_UNCHECKED_CONVERSION',
                'pattern': r'\.parse\(\)\.unwrap\(\)|\.unwrap\(\)',
                'severity': 'medium',
                'cwe': 'CWE-20',
                'description': 'Unchecked input parsing can cause panics',
                'recommendation': 'Handle parsing errors gracefully with proper error handling',
                'category': 'input_validation'
            },
            {
                'id': 'RUST_BUFFER_OVERFLOW',
                'pattern': r'\.get_unchecked\(|\.get_unchecked_mut\(',
                'severity': 'high',
                'cwe': 'CWE-119',
                'description': 'Unchecked array access can lead to buffer overflow',
                'recommendation': 'Use checked array access methods or bounds checking',
                'category': 'memory_safety'
            },
            {
                'id': 'RUST_INTEGER_OVERFLOW',
                'pattern': r'wrapping_add|wrapping_sub|wrapping_mul|overflowing_',
                'severity': 'medium',
                'cwe': 'CWE-190',
                'description': 'Explicit wrapping arithmetic may hide integer overflow bugs',
                'recommendation': 'Use checked arithmetic or ensure overflow is intentional',
                'category': 'arithmetic'
            },
            
            # File System Security
            {
                'id': 'RUST_PATH_TRAVERSAL',
                'pattern': r'Path::new\([^)]*\.\.[^)]*\)|PathBuf::from\([^)]*\.\.[^)]*\)',
                'severity': 'high',
                'cwe': 'CWE-22',
                'description': 'Potential path traversal vulnerability',
                'recommendation': 'Validate and sanitize file paths, use canonicalize()',
                'category': 'file_system'
            },
            {
                'id': 'RUST_TEMP_FILE_RACE',
                'pattern': r'std::env::temp_dir\(\)|NamedTempFile::new\(\)',
                'severity': 'medium',
                'cwe': 'CWE-377',
                'description': 'Temporary file creation may be vulnerable to race conditions',
                'recommendation': 'Use secure temporary file creation with proper permissions',
                'category': 'file_system'
            },
            
            # Network Security
            {
                'id': 'RUST_TLS_VERIFICATION_DISABLED',
                'pattern': r'danger_accept_invalid_certs\(true\)|danger_accept_invalid_hostnames\(true\)',
                'severity': 'critical',
                'cwe': 'CWE-295',
                'description': 'TLS certificate verification is disabled',
                'recommendation': 'Enable proper TLS certificate verification',
                'category': 'network_security'
            },
            {
                'id': 'RUST_HTTP_WITHOUT_TLS',
                'pattern': r'http://[^"\s]+|HttpConnector::new\(\)',
                'severity': 'medium',
                'cwe': 'CWE-319',
                'description': 'HTTP communication without encryption',
                'recommendation': 'Use HTTPS for sensitive communications',
                'category': 'network_security'
            },
            
            # Serialization Issues
            {
                'id': 'RUST_UNSAFE_DESERIALIZATION',
                'pattern': r'serde_json::from_str|bincode::deserialize|postcard::from_bytes',
                'severity': 'medium',
                'cwe': 'CWE-502',
                'description': 'Deserialization of untrusted data can be dangerous',
                'recommendation': 'Validate input data and use safe deserialization practices',
                'category': 'serialization'
            },
            
            # Command Injection
            {
                'id': 'RUST_COMMAND_INJECTION',
                'pattern': r'Command::new\([^)]*user_input[^)]*\)|std::process::Command',
                'severity': 'high',
                'cwe': 'CWE-78',
                'description': 'Potential command injection vulnerability',
                'recommendation': 'Sanitize input and use parameterized commands',
                'category': 'injection'
            },
            
            # Panic and Error Handling
            {
                'id': 'RUST_PANIC_IN_PRODUCTION',
                'pattern': r'panic!\(|unreachable!\(|unimplemented!\(',
                'severity': 'medium',
                'cwe': 'CWE-248',
                'description': 'Explicit panic can cause denial of service',
                'recommendation': 'Use proper error handling instead of panicking',
                'category': 'error_handling'
            },
            {
                'id': 'RUST_EXPECT_USAGE',
                'pattern': r'\.expect\(["\'][^"\']*["\']',
                'severity': 'low',
                'cwe': 'CWE-248',
                'description': 'Expect can cause panics in production',
                'recommendation': 'Consider using proper error handling instead of expect',
                'category': 'error_handling'
            },
            
            # FFI Security
            {
                'id': 'RUST_FFI_UNSAFE',
                'pattern': r'extern\s+"C"\s*\{|#\[link\(|CString::new|CStr::from_ptr',
                'severity': 'high',
                'cwe': 'CWE-119',
                'description': 'FFI operations bypass Rust safety guarantees',
                'recommendation': 'Carefully validate FFI boundaries and data',
                'category': 'ffi'
            },
            
            # Cargo and Dependencies
            {
                'id': 'RUST_OUTDATED_DEPENDENCIES',
                'pattern': r'version\s*=\s*["\'](?:0\.|1\.0\.|2\.0\.)["\']',
                'severity': 'low',
                'cwe': 'CWE-1104',
                'description': 'Potentially outdated dependency versions',
                'recommendation': 'Regularly update dependencies and check for security advisories',
                'category': 'dependencies'
            },
            
            # Async/Await Issues
            {
                'id': 'RUST_BLOCKING_IN_ASYNC',
                'pattern': r'async\s+fn[^{]*\{[^}]*std::thread::sleep|async\s+fn[^{]*\{[^}]*\.wait\(\)',
                'severity': 'medium',
                'cwe': 'CWE-400',
                'description': 'Blocking operations in async functions can cause performance issues',
                'recommendation': 'Use async-compatible alternatives like tokio::time::sleep',
                'category': 'async'
            },
            
            # Resource Management
            {
                'id': 'RUST_RESOURCE_LEAK',
                'pattern': r'Box::leak|ManuallyDrop::new|forget\(',
                'severity': 'medium',
                'cwe': 'CWE-401',
                'description': 'Potential resource leak',
                'recommendation': 'Ensure proper resource cleanup and avoid memory leaks',
                'category': 'resource_management'
            }
        ]
    
    def scan_code(self, code: str, filename: str = '') -> List[Dict[str, Any]]:
        """Scan Rust code for security vulnerabilities"""
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
        
        # Add Rust-specific advanced analysis
        vulnerabilities.extend(self._advanced_rust_analysis(code, lines))
        
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
        if 'test' in line.lower() or '#[test]' in line:
            base_confidence *= 0.7
        
        # Increase confidence for exact matches
        if match.group() == pattern_info.get('exact_match', ''):
            base_confidence = min(0.98, base_confidence + 0.1)
        
        return round(base_confidence, 2)
    
    def _advanced_rust_analysis(self, code: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Perform advanced Rust-specific security analysis"""
        vulnerabilities = []
        
        # Check for unsafe trait implementations
        unsafe_trait_pattern = r'unsafe\s+impl\s+.*for\s+.*\{'
        for line_num, line in enumerate(lines, 1):
            if re.search(unsafe_trait_pattern, line):
                vulnerabilities.append({
                    'type': 'Unsafe Trait Implementation',
                    'severity': 'high',
                    'line': line_num,
                    'column': 1,
                    'description': 'Unsafe trait implementation requires careful safety analysis',
                    'recommendation': 'Ensure all safety invariants are maintained',
                    'cwe': 'CWE-119',
                    'category': 'memory_safety',
                    'code_snippet': line.strip(),
                    'pattern_id': 'RUST_UNSAFE_TRAIT_IMPL',
                    'confidence': 0.85
                })
        
        # Check for potential integer overflow in array indexing
        array_index_pattern = r'\w+\[.*\+.*\]|\w+\[.*\*.*\]'
        for line_num, line in enumerate(lines, 1):
            if re.search(array_index_pattern, line) and 'get(' not in line:
                vulnerabilities.append({
                    'type': 'Potential Array Index Overflow',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'Array indexing with arithmetic operations may overflow',
                    'recommendation': 'Use checked indexing or bounds validation',
                    'cwe': 'CWE-190',
                    'category': 'arithmetic',
                    'code_snippet': line.strip(),
                    'pattern_id': 'RUST_ARRAY_INDEX_OVERFLOW',
                    'confidence': 0.75
                })
        
        # Check for potential SQL injection in database queries
        sql_pattern = r'(query|execute)\s*\(\s*&?format!\s*\(|query!\s*\(\s*&?format!\s*\('
        for line_num, line in enumerate(lines, 1):
            if re.search(sql_pattern, line):
                vulnerabilities.append({
                    'type': 'Potential SQL Injection',
                    'severity': 'high',
                    'line': line_num,
                    'column': 1,
                    'description': 'Dynamic SQL query construction may be vulnerable to injection',
                    'recommendation': 'Use parameterized queries or prepared statements',
                    'cwe': 'CWE-89',
                    'category': 'injection',
                    'code_snippet': line.strip(),
                    'pattern_id': 'RUST_SQL_INJECTION',
                    'confidence': 0.80
                })
        
        # Check for potential timing attacks in cryptographic operations
        timing_attack_pattern = r'==.*password|==.*secret|==.*token'
        for line_num, line in enumerate(lines, 1):
            if re.search(timing_attack_pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Potential Timing Attack',
                    'severity': 'medium',
                    'line': line_num,
                    'column': 1,
                    'description': 'String comparison of secrets may be vulnerable to timing attacks',
                    'recommendation': 'Use constant-time comparison functions',
                    'cwe': 'CWE-208',
                    'category': 'cryptography',
                    'code_snippet': line.strip(),
                    'pattern_id': 'RUST_TIMING_ATTACK',
                    'confidence': 0.70
                })
        
        return vulnerabilities
    
    def get_language_info(self) -> Dict[str, Any]:
        """Get information about Rust language support"""
        return {
            'language': 'rust',
            'version': '1.0.0',
            'patterns_count': len(self.patterns),
            'categories': list(set(p['category'] for p in self.patterns)),
            'severity_levels': list(set(p['severity'] for p in self.patterns)),
            'description': 'Comprehensive Rust security analysis with memory safety focus'
        }

