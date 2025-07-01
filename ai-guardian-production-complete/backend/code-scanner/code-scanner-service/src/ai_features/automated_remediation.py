"""
Automated Remediation Engine for AI Guardian
AI-powered automatic vulnerability fixes and secure code generation
"""

import re
import ast
import json
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import openai
import difflib

@dataclass
class RemediationResult:
    """Result of an automated remediation attempt"""
    success: bool
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float
    vulnerability_type: str
    changes_made: List[str]
    warnings: List[str]
    backup_created: bool

class AutomatedRemediationEngine:
    """AI-powered automated vulnerability remediation system"""
    
    def __init__(self):
        self.remediation_patterns = self._initialize_remediation_patterns()
        self.openai_client = None
        self._setup_ai_client()
        
        # Track remediation statistics
        self.remediation_stats = {
            'total_attempts': 0,
            'successful_fixes': 0,
            'failed_fixes': 0,
            'by_vulnerability_type': {},
            'by_language': {}
        }
    
    def _setup_ai_client(self):
        """Setup AI client for code generation"""
        try:
            # Try OpenRouter first for cost-effectiveness
            openrouter_key = os.getenv('OPENROUTER_API_KEY')
            if openrouter_key:
                self.openai_client = openai.OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=openrouter_key
                )
                self.model_name = "deepseek/deepseek-coder-33b-instruct"  # Good for code generation
            else:
                # Fallback to OpenAI
                openai_key = os.getenv('OPENAI_API_KEY')
                if openai_key:
                    self.openai_client = openai.OpenAI(api_key=openai_key)
                    self.model_name = "gpt-3.5-turbo"
        except Exception as e:
            print(f"Warning: Could not initialize AI client: {e}")
            self.openai_client = None
    
    def _initialize_remediation_patterns(self) -> Dict[str, Dict]:
        """Initialize patterns for automatic remediation"""
        return {
            'sql_injection': {
                'python': {
                    'patterns': [
                        {
                            'vulnerable': r'cursor\.execute\s*\(\s*["\'].*%.*["\'].*%.*\)',
                            'fix_template': 'cursor.execute("{query}", {params})',
                            'description': 'Replace string formatting with parameterized query'
                        },
                        {
                            'vulnerable': r'query\s*=\s*["\'].*\{\}.*["\']\.format\(',
                            'fix_template': 'Use parameterized queries instead of .format()',
                            'description': 'Replace .format() with parameterized queries'
                        }
                    ],
                    'imports_needed': ['sqlite3', 'psycopg2', 'pymysql']
                },
                'javascript': {
                    'patterns': [
                        {
                            'vulnerable': r'query\s*=\s*[`"\'].*\$\{.*\}.*[`"\']',
                            'fix_template': 'Use parameterized queries with ? placeholders',
                            'description': 'Replace template literals with parameterized queries'
                        }
                    ]
                }
            },
            'xss': {
                'python': {
                    'patterns': [
                        {
                            'vulnerable': r'render_template_string\s*\(\s*.*\+.*\)',
                            'fix_template': 'render_template_string(template, **safe_vars)',
                            'description': 'Use template variables instead of string concatenation'
                        }
                    ],
                    'imports_needed': ['markupsafe']
                },
                'javascript': {
                    'patterns': [
                        {
                            'vulnerable': r'innerHTML\s*=\s*.*\+.*',
                            'fix_template': 'textContent = sanitizedValue',
                            'description': 'Use textContent or proper sanitization'
                        }
                    ]
                }
            },
            'hardcoded_secrets': {
                'python': {
                    'patterns': [
                        {
                            'vulnerable': r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']',
                            'fix_template': '{var_name} = os.getenv("{env_var}", "")',
                            'description': 'Move secrets to environment variables'
                        }
                    ],
                    'imports_needed': ['os']
                },
                'javascript': {
                    'patterns': [
                        {
                            'vulnerable': r'(apiKey|secret|password|token)\s*[:=]\s*["\'][^"\']+["\']',
                            'fix_template': '{var_name} = process.env.{env_var}',
                            'description': 'Move secrets to environment variables'
                        }
                    ]
                }
            },
            'weak_crypto': {
                'python': {
                    'patterns': [
                        {
                            'vulnerable': r'hashlib\.md5\(',
                            'fix_template': 'hashlib.sha256(',
                            'description': 'Replace MD5 with SHA-256'
                        },
                        {
                            'vulnerable': r'hashlib\.sha1\(',
                            'fix_template': 'hashlib.sha256(',
                            'description': 'Replace SHA-1 with SHA-256'
                        }
                    ]
                }
            },
            'path_traversal': {
                'python': {
                    'patterns': [
                        {
                            'vulnerable': r'open\s*\(\s*.*\+.*\)',
                            'fix_template': 'open(os.path.join(safe_dir, sanitized_filename))',
                            'description': 'Use os.path.join and validate file paths'
                        }
                    ],
                    'imports_needed': ['os']
                }
            },
            'command_injection': {
                'python': {
                    'patterns': [
                        {
                            'vulnerable': r'os\.system\s*\(\s*.*\+.*\)',
                            'fix_template': 'subprocess.run([command, arg1, arg2], check=True)',
                            'description': 'Use subprocess with argument list'
                        }
                    ],
                    'imports_needed': ['subprocess']
                }
            }
        }
    
    def remediate_vulnerability(self, 
                              vulnerability: Dict[str, Any], 
                              source_code: str, 
                              file_path: str = None,
                              auto_apply: bool = False) -> RemediationResult:
        """Automatically remediate a specific vulnerability"""
        
        self.remediation_stats['total_attempts'] += 1
        
        try:
            vuln_type = vulnerability.get('type', '').lower()
            language = vulnerability.get('language', 'unknown').lower()
            line_number = vulnerability.get('line', 0)
            
            # Update statistics
            self.remediation_stats['by_vulnerability_type'][vuln_type] = \
                self.remediation_stats['by_vulnerability_type'].get(vuln_type, 0) + 1
            self.remediation_stats['by_language'][language] = \
                self.remediation_stats['by_language'].get(language, 0) + 1
            
            # Try pattern-based remediation first
            pattern_result = self._try_pattern_remediation(vulnerability, source_code, language)
            
            if pattern_result.success:
                self.remediation_stats['successful_fixes'] += 1
                
                if auto_apply and file_path:
                    self._apply_fix(file_path, pattern_result.fixed_code)
                    pattern_result.backup_created = True
                
                return pattern_result
            
            # Fall back to AI-powered remediation
            ai_result = self._try_ai_remediation(vulnerability, source_code, language)
            
            if ai_result.success:
                self.remediation_stats['successful_fixes'] += 1
                
                if auto_apply and file_path:
                    self._apply_fix(file_path, ai_result.fixed_code)
                    ai_result.backup_created = True
            else:
                self.remediation_stats['failed_fixes'] += 1
            
            return ai_result
            
        except Exception as e:
            self.remediation_stats['failed_fixes'] += 1
            return RemediationResult(
                success=False,
                original_code=source_code,
                fixed_code=source_code,
                explanation=f"Remediation failed: {str(e)}",
                confidence=0.0,
                vulnerability_type=vuln_type,
                changes_made=[],
                warnings=[f"Error during remediation: {str(e)}"],
                backup_created=False
            )
    
    def _try_pattern_remediation(self, vulnerability: Dict, source_code: str, language: str) -> RemediationResult:
        """Try pattern-based remediation using predefined patterns"""
        
        vuln_type_key = self._normalize_vulnerability_type(vulnerability.get('type', ''))
        
        if vuln_type_key not in self.remediation_patterns:
            return RemediationResult(
                success=False,
                original_code=source_code,
                fixed_code=source_code,
                explanation="No pattern-based remediation available for this vulnerability type",
                confidence=0.0,
                vulnerability_type=vuln_type_key,
                changes_made=[],
                warnings=["Pattern-based remediation not available"],
                backup_created=False
            )
        
        lang_patterns = self.remediation_patterns[vuln_type_key].get(language, {})
        if not lang_patterns:
            return RemediationResult(
                success=False,
                original_code=source_code,
                fixed_code=source_code,
                explanation=f"No pattern-based remediation available for {language}",
                confidence=0.0,
                vulnerability_type=vuln_type_key,
                changes_made=[],
                warnings=[f"No patterns for {language}"],
                backup_created=False
            )
        
        # Try each pattern
        for pattern_info in lang_patterns.get('patterns', []):
            vulnerable_pattern = pattern_info['vulnerable']
            
            if re.search(vulnerable_pattern, source_code, re.IGNORECASE):
                # Apply the fix
                fixed_code = self._apply_pattern_fix(source_code, pattern_info, lang_patterns)
                
                if fixed_code != source_code:
                    changes_made = self._generate_change_summary(source_code, fixed_code)
                    
                    return RemediationResult(
                        success=True,
                        original_code=source_code,
                        fixed_code=fixed_code,
                        explanation=pattern_info['description'],
                        confidence=0.85,
                        vulnerability_type=vuln_type_key,
                        changes_made=changes_made,
                        warnings=[],
                        backup_created=False
                    )
        
        return RemediationResult(
            success=False,
            original_code=source_code,
            fixed_code=source_code,
            explanation="No matching patterns found",
            confidence=0.0,
            vulnerability_type=vuln_type_key,
            changes_made=[],
            warnings=["No matching patterns"],
            backup_created=False
        )
    
    def _try_ai_remediation(self, vulnerability: Dict, source_code: str, language: str) -> RemediationResult:
        """Try AI-powered remediation using language models"""
        
        if not self.openai_client:
            return RemediationResult(
                success=False,
                original_code=source_code,
                fixed_code=source_code,
                explanation="AI remediation not available - API not configured",
                confidence=0.0,
                vulnerability_type=vulnerability.get('type', ''),
                changes_made=[],
                warnings=["AI client not available"],
                backup_created=False
            )
        
        try:
            # Prepare the prompt for AI remediation
            prompt = self._create_remediation_prompt(vulnerability, source_code, language)
            
            response = self.openai_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a security expert that fixes code vulnerabilities. "
                                 "Provide only the fixed code without explanations unless specifically asked. "
                                 "Maintain the original code structure and functionality while fixing security issues."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.1  # Low temperature for consistent, deterministic fixes
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Extract the fixed code from the AI response
            fixed_code = self._extract_code_from_ai_response(ai_response, language)
            
            if fixed_code and fixed_code != source_code:
                changes_made = self._generate_change_summary(source_code, fixed_code)
                confidence = self._calculate_ai_fix_confidence(source_code, fixed_code, vulnerability)
                
                return RemediationResult(
                    success=True,
                    original_code=source_code,
                    fixed_code=fixed_code,
                    explanation="AI-powered vulnerability remediation applied",
                    confidence=confidence,
                    vulnerability_type=vulnerability.get('type', ''),
                    changes_made=changes_made,
                    warnings=self._validate_ai_fix(source_code, fixed_code, language),
                    backup_created=False
                )
            else:
                return RemediationResult(
                    success=False,
                    original_code=source_code,
                    fixed_code=source_code,
                    explanation="AI could not generate a valid fix",
                    confidence=0.0,
                    vulnerability_type=vulnerability.get('type', ''),
                    changes_made=[],
                    warnings=["AI fix validation failed"],
                    backup_created=False
                )
                
        except Exception as e:
            return RemediationResult(
                success=False,
                original_code=source_code,
                fixed_code=source_code,
                explanation=f"AI remediation failed: {str(e)}",
                confidence=0.0,
                vulnerability_type=vulnerability.get('type', ''),
                changes_made=[],
                warnings=[f"AI error: {str(e)}"],
                backup_created=False
            )
    
    def _normalize_vulnerability_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for pattern matching"""
        vuln_type = vuln_type.lower()
        
        # Map common variations to standard types
        type_mappings = {
            'sql injection': 'sql_injection',
            'sqli': 'sql_injection',
            'cross-site scripting': 'xss',
            'cross site scripting': 'xss',
            'hardcoded secret': 'hardcoded_secrets',
            'hardcoded password': 'hardcoded_secrets',
            'weak cryptography': 'weak_crypto',
            'weak crypto': 'weak_crypto',
            'path traversal': 'path_traversal',
            'directory traversal': 'path_traversal',
            'command injection': 'command_injection',
            'code injection': 'command_injection'
        }
        
        return type_mappings.get(vuln_type, vuln_type.replace(' ', '_'))
    
    def _apply_pattern_fix(self, source_code: str, pattern_info: Dict, lang_patterns: Dict) -> str:
        """Apply a pattern-based fix to the source code"""
        vulnerable_pattern = pattern_info['vulnerable']
        fix_template = pattern_info['fix_template']
        
        # Simple regex replacement for now
        # In a production system, this would be more sophisticated
        fixed_code = re.sub(vulnerable_pattern, fix_template, source_code, flags=re.IGNORECASE)
        
        # Add necessary imports if specified
        if 'imports_needed' in lang_patterns:
            fixed_code = self._add_imports(fixed_code, lang_patterns['imports_needed'])
        
        return fixed_code
    
    def _add_imports(self, code: str, imports_needed: List[str]) -> str:
        """Add necessary imports to the code"""
        lines = code.split('\n')
        import_lines = []
        
        for imp in imports_needed:
            import_line = f"import {imp}"
            if import_line not in code:
                import_lines.append(import_line)
        
        if import_lines:
            # Find the best place to insert imports
            insert_index = 0
            for i, line in enumerate(lines):
                if line.strip().startswith('import ') or line.strip().startswith('from '):
                    insert_index = i + 1
                elif line.strip() and not line.strip().startswith('#'):
                    break
            
            # Insert imports
            for imp_line in reversed(import_lines):
                lines.insert(insert_index, imp_line)
        
        return '\n'.join(lines)
    
    def _create_remediation_prompt(self, vulnerability: Dict, source_code: str, language: str) -> str:
        """Create a prompt for AI-powered remediation"""
        
        prompt = f"""Fix the following {language} code to resolve this security vulnerability:

Vulnerability Type: {vulnerability.get('type', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Description: {vulnerability.get('description', 'No description')}
Line: {vulnerability.get('line', 'Unknown')}

Original Code:
```{language}
{source_code}
```

Please provide the fixed code that:
1. Resolves the security vulnerability
2. Maintains the original functionality
3. Follows security best practices
4. Is syntactically correct

Fixed Code:"""
        
        return prompt
    
    def _extract_code_from_ai_response(self, ai_response: str, language: str) -> str:
        """Extract code from AI response"""
        # Look for code blocks
        code_block_pattern = rf'```{language}?\s*\n(.*?)\n```'
        match = re.search(code_block_pattern, ai_response, re.DOTALL | re.IGNORECASE)
        
        if match:
            return match.group(1).strip()
        
        # If no code block found, try to extract code after "Fixed Code:" or similar
        lines = ai_response.split('\n')
        code_started = False
        code_lines = []
        
        for line in lines:
            if 'fixed code' in line.lower() or 'corrected code' in line.lower():
                code_started = True
                continue
            
            if code_started:
                code_lines.append(line)
        
        if code_lines:
            return '\n'.join(code_lines).strip()
        
        # Last resort: return the entire response
        return ai_response.strip()
    
    def _calculate_ai_fix_confidence(self, original: str, fixed: str, vulnerability: Dict) -> float:
        """Calculate confidence score for AI-generated fix"""
        base_confidence = 0.7
        
        # Check if the fix actually changed something
        if original == fixed:
            return 0.0
        
        # Check if the fix is syntactically valid (basic check)
        try:
            if vulnerability.get('language', '').lower() == 'python':
                ast.parse(fixed)
                base_confidence += 0.1
        except:
            base_confidence -= 0.3
        
        # Check if the vulnerable pattern is removed
        vuln_pattern = vulnerability.get('pattern', '')
        if vuln_pattern and not re.search(vuln_pattern, fixed, re.IGNORECASE):
            base_confidence += 0.1
        
        # Check for common security improvements
        security_improvements = [
            'parameterized', 'sanitize', 'escape', 'validate',
            'os.getenv', 'process.env', 'secure', 'safe'
        ]
        
        for improvement in security_improvements:
            if improvement in fixed.lower() and improvement not in original.lower():
                base_confidence += 0.05
        
        return min(0.95, max(0.1, base_confidence))
    
    def _validate_ai_fix(self, original: str, fixed: str, language: str) -> List[str]:
        """Validate AI-generated fix and return warnings"""
        warnings = []
        
        # Check for syntax validity
        try:
            if language.lower() == 'python':
                ast.parse(fixed)
        except SyntaxError as e:
            warnings.append(f"Syntax error in fixed code: {str(e)}")
        
        # Check if fix is too different from original
        similarity = difflib.SequenceMatcher(None, original, fixed).ratio()
        if similarity < 0.3:
            warnings.append("Fixed code is significantly different from original - manual review recommended")
        
        # Check for potential issues
        if len(fixed) < len(original) * 0.5:
            warnings.append("Fixed code is much shorter - functionality may be lost")
        
        if 'TODO' in fixed or 'FIXME' in fixed:
            warnings.append("Fixed code contains TODO/FIXME comments - incomplete fix")
        
        return warnings
    
    def _generate_change_summary(self, original: str, fixed: str) -> List[str]:
        """Generate a summary of changes made"""
        changes = []
        
        # Use difflib to find differences
        diff = list(difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile='original',
            tofile='fixed',
            n=0
        ))
        
        added_lines = 0
        removed_lines = 0
        
        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                added_lines += 1
            elif line.startswith('-') and not line.startswith('---'):
                removed_lines += 1
        
        if added_lines > 0:
            changes.append(f"Added {added_lines} lines")
        if removed_lines > 0:
            changes.append(f"Removed {removed_lines} lines")
        
        # Look for specific types of changes
        if 'import ' in fixed and 'import ' not in original:
            changes.append("Added security-related imports")
        
        if 'os.getenv' in fixed or 'process.env' in fixed:
            changes.append("Moved secrets to environment variables")
        
        if any(word in fixed.lower() for word in ['parameterized', 'prepared', 'sanitize']):
            changes.append("Implemented secure coding practices")
        
        return changes if changes else ["Code structure modified"]
    
    def _apply_fix(self, file_path: str, fixed_code: str):
        """Apply the fix to the actual file"""
        # Create backup
        backup_path = f"{file_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Read original file
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Create backup
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(original_content)
            
            # Write fixed code
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_code)
                
        except Exception as e:
            raise Exception(f"Failed to apply fix: {str(e)}")
    
    def batch_remediate(self, vulnerabilities: List[Dict], source_files: Dict[str, str]) -> Dict[str, RemediationResult]:
        """Remediate multiple vulnerabilities in batch"""
        results = {}
        
        for vuln in vulnerabilities:
            file_path = vuln.get('file_path', '')
            if file_path in source_files:
                source_code = source_files[file_path]
                result = self.remediate_vulnerability(vuln, source_code, file_path)
                results[f"{file_path}:{vuln.get('line', 0)}"] = result
        
        return results
    
    def get_remediation_statistics(self) -> Dict[str, Any]:
        """Get remediation statistics"""
        success_rate = 0.0
        if self.remediation_stats['total_attempts'] > 0:
            success_rate = (self.remediation_stats['successful_fixes'] / 
                          self.remediation_stats['total_attempts']) * 100
        
        return {
            'total_attempts': self.remediation_stats['total_attempts'],
            'successful_fixes': self.remediation_stats['successful_fixes'],
            'failed_fixes': self.remediation_stats['failed_fixes'],
            'success_rate': round(success_rate, 2),
            'by_vulnerability_type': self.remediation_stats['by_vulnerability_type'],
            'by_language': self.remediation_stats['by_language']
        }
    
    def generate_secure_code(self, description: str, language: str, context: Dict = None) -> str:
        """Generate secure code based on description"""
        if not self.openai_client:
            return "# AI code generation not available - API not configured"
        
        try:
            prompt = f"""Generate secure {language} code for the following requirement:

{description}

Requirements:
1. Follow security best practices
2. Include input validation
3. Use secure coding patterns
4. Add appropriate error handling
5. Include security comments where relevant

Context: {json.dumps(context) if context else 'None'}

Secure {language} Code:"""

            response = self.openai_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security-focused code generator. Always prioritize security in your code generation."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.2
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            return f"# Error generating secure code: {str(e)}"

