"""
Natural Language Query Processor for AI Guardian
Allows users to ask security, privacy, and compliance questions in plain English
"""

import re
import json
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import openai
import os
from dataclasses import dataclass

@dataclass
class QueryResult:
    """Result of a natural language query"""
    answer: str
    confidence: float
    sources: List[str]
    related_vulnerabilities: List[Dict]
    recommendations: List[str]
    query_type: str

class NaturalLanguageProcessor:
    """Process natural language queries about security, privacy, and compliance"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
        self.query_patterns = self._initialize_query_patterns()
        self.knowledge_base = self._load_knowledge_base()
        
        # Initialize OpenAI client (using cost-effective options)
        self.openai_client = None
        self._setup_ai_client()
    
    def _setup_ai_client(self):
        """Setup AI client with cost-effective options"""
        try:
            # Try to use OpenRouter for cost-effective API access
            openrouter_key = os.getenv('OPENROUTER_API_KEY')
            if openrouter_key:
                self.openai_client = openai.OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=openrouter_key
                )
                self.model_name = "microsoft/wizardlm-2-8x22b"  # Cost-effective model
            else:
                # Fallback to OpenAI
                openai_key = os.getenv('OPENAI_API_KEY')
                if openai_key:
                    self.openai_client = openai.OpenAI(api_key=openai_key)
                    self.model_name = "gpt-3.5-turbo"  # More cost-effective than GPT-4
        except Exception as e:
            print(f"Warning: Could not initialize AI client: {e}")
            self.openai_client = None
    
    def _initialize_query_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize patterns for different types of queries"""
        return {
            'vulnerability_search': [
                {
                    'pattern': r'(?:what|which|show|find|list).*(?:vulnerabilities|security issues|bugs).*(?:in|for|with)\s+(\w+)',
                    'intent': 'find_vulnerabilities_by_language',
                    'confidence': 0.9
                },
                {
                    'pattern': r'(?:how many|count).*(?:vulnerabilities|issues).*(?:critical|high|medium|low)',
                    'intent': 'count_vulnerabilities_by_severity',
                    'confidence': 0.85
                },
                {
                    'pattern': r'(?:show|list|find).*(?:recent|latest|new).*(?:vulnerabilities|scans)',
                    'intent': 'recent_vulnerabilities',
                    'confidence': 0.8
                }
            ],
            'compliance_queries': [
                {
                    'pattern': r'(?:gdpr|ccpa|hipaa|sox|pci-dss).*(?:compliance|violations|requirements)',
                    'intent': 'compliance_status',
                    'confidence': 0.9
                },
                {
                    'pattern': r'(?:what|which).*(?:regulations|compliance).*(?:apply|required|needed)',
                    'intent': 'applicable_regulations',
                    'confidence': 0.85
                },
                {
                    'pattern': r'(?:how to|steps to).*(?:comply|fix|resolve).*(?:gdpr|ccpa|hipaa|sox|pci-dss)',
                    'intent': 'compliance_remediation',
                    'confidence': 0.8
                }
            ],
            'security_best_practices': [
                {
                    'pattern': r'(?:best practices|recommendations|how to).*(?:secure|protect|harden)',
                    'intent': 'security_recommendations',
                    'confidence': 0.85
                },
                {
                    'pattern': r'(?:how to|prevent|avoid).*(?:sql injection|xss|csrf|injection)',
                    'intent': 'vulnerability_prevention',
                    'confidence': 0.9
                },
                {
                    'pattern': r'(?:secure coding|security guidelines).*(?:for|in)\s+(\w+)',
                    'intent': 'language_security_guidelines',
                    'confidence': 0.8
                }
            ],
            'threat_analysis': [
                {
                    'pattern': r'(?:threat|risk).*(?:analysis|assessment|level)',
                    'intent': 'threat_assessment',
                    'confidence': 0.85
                },
                {
                    'pattern': r'(?:what|which).*(?:threats|attacks).*(?:possible|likely|common)',
                    'intent': 'common_threats',
                    'confidence': 0.8
                },
                {
                    'pattern': r'(?:impact|damage|consequences).*(?:if|when).*(?:exploited|attacked)',
                    'intent': 'impact_analysis',
                    'confidence': 0.75
                }
            ]
        }
    
    def _load_knowledge_base(self) -> Dict[str, Any]:
        """Load security knowledge base"""
        return {
            'vulnerability_types': {
                'sql_injection': {
                    'description': 'SQL injection occurs when user input is inserted into SQL queries without proper sanitization',
                    'severity': 'critical',
                    'prevention': 'Use parameterized queries, input validation, and least privilege database access',
                    'cwe': 'CWE-89'
                },
                'xss': {
                    'description': 'Cross-site scripting allows attackers to inject malicious scripts into web pages',
                    'severity': 'high',
                    'prevention': 'Use output encoding, Content Security Policy, and input validation',
                    'cwe': 'CWE-79'
                },
                'csrf': {
                    'description': 'Cross-site request forgery tricks users into performing unintended actions',
                    'severity': 'medium',
                    'prevention': 'Use CSRF tokens, SameSite cookies, and proper authentication',
                    'cwe': 'CWE-352'
                }
            },
            'compliance_frameworks': {
                'gdpr': {
                    'name': 'General Data Protection Regulation',
                    'scope': 'EU data protection',
                    'key_requirements': ['consent', 'data minimization', 'right to erasure', 'data portability'],
                    'penalties': 'Up to 4% of annual revenue or €20 million'
                },
                'hipaa': {
                    'name': 'Health Insurance Portability and Accountability Act',
                    'scope': 'Healthcare data protection',
                    'key_requirements': ['PHI encryption', 'access controls', 'audit logs', 'breach notification'],
                    'penalties': 'Up to $1.5 million per incident'
                },
                'pci_dss': {
                    'name': 'Payment Card Industry Data Security Standard',
                    'scope': 'Payment card data protection',
                    'key_requirements': ['encryption', 'access controls', 'network security', 'monitoring'],
                    'penalties': 'Fines and loss of processing privileges'
                }
            },
            'security_best_practices': {
                'python': [
                    'Use parameterized queries for database operations',
                    'Validate and sanitize all user input',
                    'Use secure random number generation',
                    'Implement proper error handling',
                    'Keep dependencies updated'
                ],
                'javascript': [
                    'Use Content Security Policy',
                    'Sanitize user input before DOM manipulation',
                    'Implement proper authentication',
                    'Use HTTPS for all communications',
                    'Validate data on both client and server'
                ],
                'general': [
                    'Follow principle of least privilege',
                    'Implement defense in depth',
                    'Regular security testing and code reviews',
                    'Keep software and dependencies updated',
                    'Use strong authentication and authorization'
                ]
            }
        }
    
    def process_query(self, query: str, user_context: Dict = None) -> QueryResult:
        """Process a natural language query and return structured results"""
        try:
            # Normalize query
            normalized_query = query.lower().strip()
            
            # Determine query intent
            intent, confidence, extracted_params = self._analyze_intent(normalized_query)
            
            # Process based on intent
            if intent.startswith('find_vulnerabilities'):
                result = self._handle_vulnerability_search(normalized_query, extracted_params, user_context)
            elif intent.startswith('compliance'):
                result = self._handle_compliance_query(normalized_query, extracted_params, user_context)
            elif intent.startswith('security_recommendations'):
                result = self._handle_security_recommendations(normalized_query, extracted_params, user_context)
            elif intent.startswith('threat'):
                result = self._handle_threat_analysis(normalized_query, extracted_params, user_context)
            else:
                # Use AI for complex queries
                result = self._handle_ai_query(query, user_context)
            
            result.query_type = intent
            result.confidence = min(result.confidence, confidence)
            
            return result
            
        except Exception as e:
            return QueryResult(
                answer=f"I encountered an error processing your query: {str(e)}",
                confidence=0.0,
                sources=[],
                related_vulnerabilities=[],
                recommendations=[],
                query_type='error'
            )
    
    def _analyze_intent(self, query: str) -> Tuple[str, float, Dict]:
        """Analyze query intent using pattern matching"""
        best_match = None
        best_confidence = 0.0
        extracted_params = {}
        
        for category, patterns in self.query_patterns.items():
            for pattern_info in patterns:
                match = re.search(pattern_info['pattern'], query, re.IGNORECASE)
                if match and pattern_info['confidence'] > best_confidence:
                    best_match = pattern_info['intent']
                    best_confidence = pattern_info['confidence']
                    
                    # Extract parameters from match groups
                    if match.groups():
                        extracted_params['extracted_term'] = match.group(1)
        
        return best_match or 'general_query', best_confidence, extracted_params
    
    def _handle_vulnerability_search(self, query: str, params: Dict, context: Dict) -> QueryResult:
        """Handle vulnerability search queries"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            vulnerabilities = []
            answer = ""
            
            if 'extracted_term' in params:
                # Search by language or technology
                language = params['extracted_term']
                cursor.execute("""
                    SELECT * FROM scan_results 
                    WHERE language = ? OR code_snippet LIKE ?
                    ORDER BY created_at DESC LIMIT 10
                """, (language, f'%{language}%'))
                
                results = cursor.fetchall()
                vulnerabilities = [dict(zip([col[0] for col in cursor.description], row)) for row in results]
                
                if vulnerabilities:
                    answer = f"Found {len(vulnerabilities)} vulnerabilities related to {language}. "
                    severity_counts = {}
                    for vuln in vulnerabilities:
                        severity = vuln.get('severity', 'unknown')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    answer += "Breakdown by severity: " + ", ".join([f"{k}: {v}" for k, v in severity_counts.items()])
                else:
                    answer = f"No vulnerabilities found for {language}."
            
            elif 'critical' in query or 'high' in query or 'medium' in query or 'low' in query:
                # Search by severity
                severity_terms = ['critical', 'high', 'medium', 'low']
                severity = next((term for term in severity_terms if term in query), 'high')
                
                cursor.execute("""
                    SELECT * FROM scan_results 
                    WHERE severity = ?
                    ORDER BY created_at DESC LIMIT 10
                """, (severity.upper(),))
                
                results = cursor.fetchall()
                vulnerabilities = [dict(zip([col[0] for col in cursor.description], row)) for row in results]
                
                answer = f"Found {len(vulnerabilities)} {severity} severity vulnerabilities."
            
            conn.close()
            
            recommendations = self._generate_vulnerability_recommendations(vulnerabilities)
            
            return QueryResult(
                answer=answer,
                confidence=0.85,
                sources=['vulnerability_database'],
                related_vulnerabilities=vulnerabilities[:5],  # Limit to top 5
                recommendations=recommendations,
                query_type='vulnerability_search'
            )
            
        except Exception as e:
            return QueryResult(
                answer=f"Error searching vulnerabilities: {str(e)}",
                confidence=0.0,
                sources=[],
                related_vulnerabilities=[],
                recommendations=[],
                query_type='error'
            )
    
    def _handle_compliance_query(self, query: str, params: Dict, context: Dict) -> QueryResult:
        """Handle compliance-related queries"""
        regulations = ['gdpr', 'hipaa', 'pci-dss', 'sox', 'ccpa']
        mentioned_regulation = next((reg for reg in regulations if reg.replace('-', '') in query), None)
        
        if mentioned_regulation:
            regulation_info = self.knowledge_base['compliance_frameworks'].get(mentioned_regulation, {})
            
            answer = f"**{regulation_info.get('name', mentioned_regulation.upper())}**\n\n"
            answer += f"Scope: {regulation_info.get('scope', 'Not specified')}\n\n"
            
            if 'key_requirements' in regulation_info:
                answer += "Key Requirements:\n"
                for req in regulation_info['key_requirements']:
                    answer += f"• {req}\n"
            
            if 'penalties' in regulation_info:
                answer += f"\nPenalties: {regulation_info['penalties']}"
            
            recommendations = [
                f"Conduct a {mentioned_regulation.upper()} compliance assessment",
                "Implement required security controls",
                "Document compliance procedures",
                "Regular compliance monitoring and auditing"
            ]
        else:
            answer = "I can help with GDPR, HIPAA, PCI-DSS, SOX, and CCPA compliance questions. Please specify which regulation you're interested in."
            recommendations = ["Specify a particular compliance framework for detailed guidance"]
        
        return QueryResult(
            answer=answer,
            confidence=0.8,
            sources=['compliance_knowledge_base'],
            related_vulnerabilities=[],
            recommendations=recommendations,
            query_type='compliance'
        )
    
    def _handle_security_recommendations(self, query: str, params: Dict, context: Dict) -> QueryResult:
        """Handle security best practices queries"""
        language = params.get('extracted_term', 'general')
        
        practices = self.knowledge_base['security_best_practices'].get(language, 
                    self.knowledge_base['security_best_practices']['general'])
        
        answer = f"Security best practices for {language}:\n\n"
        for i, practice in enumerate(practices, 1):
            answer += f"{i}. {practice}\n"
        
        recommendations = [
            "Implement these practices in your development workflow",
            "Regular security code reviews",
            "Use automated security scanning tools",
            "Keep security knowledge up to date"
        ]
        
        return QueryResult(
            answer=answer,
            confidence=0.85,
            sources=['security_best_practices'],
            related_vulnerabilities=[],
            recommendations=recommendations,
            query_type='security_recommendations'
        )
    
    def _handle_threat_analysis(self, query: str, params: Dict, context: Dict) -> QueryResult:
        """Handle threat analysis queries"""
        answer = "**Threat Analysis Overview**\n\n"
        answer += "Common security threats include:\n\n"
        answer += "• **Injection Attacks**: SQL injection, command injection, code injection\n"
        answer += "• **Cross-Site Scripting (XSS)**: Reflected, stored, and DOM-based XSS\n"
        answer += "• **Authentication Flaws**: Weak passwords, session management issues\n"
        answer += "• **Sensitive Data Exposure**: Unencrypted data, weak cryptography\n"
        answer += "• **Security Misconfiguration**: Default settings, unnecessary features\n"
        answer += "• **Vulnerable Dependencies**: Outdated libraries with known vulnerabilities\n\n"
        answer += "Risk levels depend on your specific application and environment."
        
        recommendations = [
            "Conduct regular threat modeling exercises",
            "Implement defense-in-depth security strategy",
            "Regular penetration testing and vulnerability assessments",
            "Keep all software components updated",
            "Monitor for security incidents and anomalies"
        ]
        
        return QueryResult(
            answer=answer,
            confidence=0.8,
            sources=['threat_intelligence'],
            related_vulnerabilities=[],
            recommendations=recommendations,
            query_type='threat_analysis'
        )
    
    def _handle_ai_query(self, query: str, context: Dict) -> QueryResult:
        """Handle complex queries using AI"""
        if not self.openai_client:
            return QueryResult(
                answer="AI-powered responses are not available. Please check your API configuration.",
                confidence=0.0,
                sources=[],
                related_vulnerabilities=[],
                recommendations=[],
                query_type='ai_unavailable'
            )
        
        try:
            system_prompt = """You are an AI security expert assistant for AI Guardian. 
            Provide accurate, helpful information about cybersecurity, privacy, and compliance.
            Focus on practical, actionable advice. Keep responses concise but comprehensive.
            If you're not certain about something, say so."""
            
            response = self.openai_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": query}
                ],
                max_tokens=500,
                temperature=0.3
            )
            
            answer = response.choices[0].message.content
            
            # Generate recommendations based on the query topic
            recommendations = self._generate_ai_recommendations(query, answer)
            
            return QueryResult(
                answer=answer,
                confidence=0.75,
                sources=['ai_assistant'],
                related_vulnerabilities=[],
                recommendations=recommendations,
                query_type='ai_powered'
            )
            
        except Exception as e:
            return QueryResult(
                answer=f"AI assistant is temporarily unavailable: {str(e)}",
                confidence=0.0,
                sources=[],
                related_vulnerabilities=[],
                recommendations=[],
                query_type='ai_error'
            )
    
    def _generate_vulnerability_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate recommendations based on found vulnerabilities"""
        recommendations = []
        
        if not vulnerabilities:
            return ["No specific recommendations - no vulnerabilities found"]
        
        # Analyze vulnerability types
        vuln_types = [v.get('type', '').lower() for v in vulnerabilities]
        
        if any('sql' in vtype for vtype in vuln_types):
            recommendations.append("Implement parameterized queries to prevent SQL injection")
        
        if any('xss' in vtype for vtype in vuln_types):
            recommendations.append("Use proper output encoding and Content Security Policy")
        
        if any('secret' in vtype or 'password' in vtype for vtype in vuln_types):
            recommendations.append("Move secrets to environment variables or secure vaults")
        
        # General recommendations
        recommendations.extend([
            "Conduct regular security code reviews",
            "Implement automated security testing in CI/CD pipeline",
            "Keep dependencies updated and monitor for vulnerabilities"
        ])
        
        return recommendations[:5]  # Limit to top 5
    
    def _generate_ai_recommendations(self, query: str, answer: str) -> List[str]:
        """Generate recommendations based on AI query and response"""
        recommendations = []
        
        query_lower = query.lower()
        
        if 'security' in query_lower:
            recommendations.append("Implement a comprehensive security strategy")
        
        if 'compliance' in query_lower:
            recommendations.append("Regular compliance audits and documentation")
        
        if 'vulnerability' in query_lower:
            recommendations.append("Automated vulnerability scanning and remediation")
        
        recommendations.extend([
            "Stay updated with latest security best practices",
            "Regular security training for development team"
        ])
        
        return recommendations[:3]  # Limit to top 3
    
    def get_query_suggestions(self, partial_query: str = "") -> List[str]:
        """Get query suggestions based on partial input"""
        suggestions = [
            "What vulnerabilities were found in Python code?",
            "How many critical vulnerabilities do we have?",
            "Show me recent security scans",
            "What are GDPR compliance requirements?",
            "How to prevent SQL injection attacks?",
            "Best practices for secure coding in JavaScript",
            "What threats should I be concerned about?",
            "How to fix XSS vulnerabilities?",
            "PCI-DSS compliance checklist",
            "Recent vulnerability trends in our codebase"
        ]
        
        if partial_query:
            # Filter suggestions based on partial query
            partial_lower = partial_query.lower()
            suggestions = [s for s in suggestions if partial_lower in s.lower()]
        
        return suggestions[:5]  # Return top 5 suggestions

