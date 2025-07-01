"""
Solidity Smart Contract Security Analyzer
Comprehensive analysis of Solidity smart contracts for vulnerabilities and optimizations
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging

class SolidityAnalyzer:
    """
    Advanced Solidity Smart Contract Analyzer
    
    Features:
    - Vulnerability detection (reentrancy, overflow, etc.)
    - Gas optimization analysis
    - Best practices compliance
    - DeFi-specific security checks
    - Formal verification patterns
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Vulnerability patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        # Gas optimization patterns
        self.gas_patterns = self._load_gas_patterns()
        
        # Best practices rules
        self.best_practices = self._load_best_practices()
        
        # DeFi security patterns
        self.defi_patterns = self._load_defi_patterns()
        
        self.logger.info("SolidityAnalyzer initialized successfully")
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[Dict]]:
        """Load Solidity vulnerability patterns"""
        return {
            "reentrancy": [
                {
                    "pattern": r"\.call\s*\(\s*[^)]*\)\s*;.*balances\[",
                    "severity": "critical",
                    "description": "Potential reentrancy vulnerability - external call before state change",
                    "cwe": "CWE-841"
                },
                {
                    "pattern": r"\.transfer\s*\([^)]*\).*balances\[",
                    "severity": "medium",
                    "description": "State change after transfer - potential reentrancy",
                    "cwe": "CWE-841"
                }
            ],
            "integer_overflow": [
                {
                    "pattern": r"(?<!using\s+SafeMath\s+for\s+uint256;).*\+\s*\w+(?!\s*\.add\()",
                    "severity": "high",
                    "description": "Potential integer overflow - use SafeMath",
                    "cwe": "CWE-190"
                },
                {
                    "pattern": r"(?<!using\s+SafeMath\s+for\s+uint256;).*\*\s*\w+(?!\s*\.mul\()",
                    "severity": "high",
                    "description": "Potential integer overflow in multiplication",
                    "cwe": "CWE-190"
                }
            ],
            "unchecked_call": [
                {
                    "pattern": r"\.call\s*\([^)]*\)\s*;(?!\s*(require|assert|if))",
                    "severity": "high",
                    "description": "Unchecked external call return value",
                    "cwe": "CWE-252"
                },
                {
                    "pattern": r"\.send\s*\([^)]*\)\s*;(?!\s*(require|assert|if))",
                    "severity": "medium",
                    "description": "Unchecked send return value",
                    "cwe": "CWE-252"
                }
            ],
            "tx_origin": [
                {
                    "pattern": r"tx\.origin\s*==",
                    "severity": "medium",
                    "description": "Use of tx.origin for authorization is vulnerable to phishing",
                    "cwe": "CWE-346"
                }
            ],
            "timestamp_dependence": [
                {
                    "pattern": r"block\.timestamp\s*[<>=]",
                    "severity": "medium",
                    "description": "Timestamp dependence can be manipulated by miners",
                    "cwe": "CWE-829"
                },
                {
                    "pattern": r"now\s*[<>=]",
                    "severity": "medium",
                    "description": "Timestamp dependence using 'now' keyword",
                    "cwe": "CWE-829"
                }
            ],
            "uninitialized_storage": [
                {
                    "pattern": r"struct\s+\w+\s+\w+\s*;(?!\s*\w+\s*=)",
                    "severity": "medium",
                    "description": "Uninitialized storage pointer",
                    "cwe": "CWE-824"
                }
            ],
            "delegatecall": [
                {
                    "pattern": r"\.delegatecall\s*\(",
                    "severity": "high",
                    "description": "Delegatecall to untrusted contract can be dangerous",
                    "cwe": "CWE-829"
                }
            ],
            "selfdestruct": [
                {
                    "pattern": r"selfdestruct\s*\(",
                    "severity": "critical",
                    "description": "Selfdestruct can be called by unauthorized users",
                    "cwe": "CWE-284"
                }
            ],
            "randomness": [
                {
                    "pattern": r"block\.blockhash\s*\(",
                    "severity": "medium",
                    "description": "Weak randomness source - blockhash can be predicted",
                    "cwe": "CWE-338"
                },
                {
                    "pattern": r"block\.difficulty",
                    "severity": "medium",
                    "description": "Block difficulty is not a secure randomness source",
                    "cwe": "CWE-338"
                }
            ]
        }
    
    def _load_gas_patterns(self) -> Dict[str, List[Dict]]:
        """Load gas optimization patterns"""
        return {
            "storage_optimization": [
                {
                    "pattern": r"uint8\s+\w+;\s*uint256\s+\w+;",
                    "optimization": "Pack smaller types together to save storage slots",
                    "gas_saved": "~20000 per slot"
                },
                {
                    "pattern": r"bool\s+\w+;\s*uint256\s+\w+;",
                    "optimization": "Pack bool with other small types",
                    "gas_saved": "~20000 per slot"
                }
            ],
            "loop_optimization": [
                {
                    "pattern": r"for\s*\([^)]*\.length[^)]*\)",
                    "optimization": "Cache array length outside loop",
                    "gas_saved": "~3 gas per iteration"
                },
                {
                    "pattern": r"for\s*\([^)]*\+\+\s*\)",
                    "optimization": "Use ++i instead of i++ in loops",
                    "gas_saved": "~5 gas per iteration"
                }
            ],
            "function_optimization": [
                {
                    "pattern": r"function\s+\w+\s*\([^)]*\)\s+public",
                    "optimization": "Use external instead of public for functions not called internally",
                    "gas_saved": "~15-20 gas"
                },
                {
                    "pattern": r"require\s*\([^,)]*,\s*\"[^\"]*\"\s*\)",
                    "optimization": "Use custom errors instead of string messages",
                    "gas_saved": "~50 gas per require"
                }
            ],
            "memory_optimization": [
                {
                    "pattern": r"string\s+memory\s+\w+\s*=\s*\"",
                    "optimization": "Use bytes32 for short strings",
                    "gas_saved": "~100-200 gas"
                }
            ]
        }
    
    def _load_best_practices(self) -> Dict[str, List[Dict]]:
        """Load Solidity best practices"""
        return {
            "access_control": [
                {
                    "pattern": r"function\s+\w+.*public(?!.*onlyOwner|.*modifier)",
                    "recommendation": "Add access control modifiers to sensitive functions",
                    "severity": "medium"
                }
            ],
            "input_validation": [
                {
                    "pattern": r"function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)(?!.*require.*!=.*address\(0\))",
                    "recommendation": "Validate address parameters are not zero address",
                    "severity": "low"
                }
            ],
            "event_emission": [
                {
                    "pattern": r"balances\[\w+\]\s*=.*(?!.*emit)",
                    "recommendation": "Emit events for important state changes",
                    "severity": "low"
                }
            ],
            "error_handling": [
                {
                    "pattern": r"assert\s*\(",
                    "recommendation": "Use require() instead of assert() for input validation",
                    "severity": "low"
                }
            ]
        }
    
    def _load_defi_patterns(self) -> Dict[str, List[Dict]]:
        """Load DeFi-specific security patterns"""
        return {
            "price_manipulation": [
                {
                    "pattern": r"getAmountsOut\s*\([^)]*\)(?!.*oracle)",
                    "severity": "high",
                    "description": "Price fetched from DEX without oracle validation",
                    "recommendation": "Use price oracles for critical price data"
                }
            ],
            "flash_loan_protection": [
                {
                    "pattern": r"function\s+\w+.*external(?!.*nonReentrant)",
                    "severity": "medium",
                    "description": "External function without reentrancy protection",
                    "recommendation": "Add reentrancy guards to external functions"
                }
            ],
            "slippage_protection": [
                {
                    "pattern": r"swapExactTokensForTokens\s*\([^)]*,\s*0\s*,",
                    "severity": "medium",
                    "description": "Swap without minimum amount protection",
                    "recommendation": "Set appropriate minimum output amounts"
                }
            ],
            "liquidity_risks": [
                {
                    "pattern": r"removeLiquidity\s*\([^)]*\)(?!.*deadline)",
                    "severity": "low",
                    "description": "Liquidity removal without deadline",
                    "recommendation": "Set transaction deadlines"
                }
            ]
        }
    
    def analyze_contract(self, contract_code: str, contract_address: Optional[str] = None) -> Dict[str, Any]:
        """Perform comprehensive Solidity contract analysis"""
        try:
            analysis_result = {
                "vulnerabilities": [],
                "gas_optimizations": [],
                "best_practices": [],
                "defi_security": [],
                "contract_metrics": {},
                "security_score": 0,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
            # Vulnerability analysis
            vulnerabilities = self._detect_vulnerabilities(contract_code)
            analysis_result["vulnerabilities"] = vulnerabilities
            
            # Gas optimization analysis
            gas_optimizations = self._analyze_gas_optimization(contract_code)
            analysis_result["gas_optimizations"] = gas_optimizations
            
            # Best practices analysis
            best_practices = self._check_best_practices(contract_code)
            analysis_result["best_practices"] = best_practices
            
            # DeFi security analysis
            defi_security = self._analyze_defi_security(contract_code)
            analysis_result["defi_security"] = defi_security
            
            # Contract metrics
            metrics = self._calculate_contract_metrics(contract_code)
            analysis_result["contract_metrics"] = metrics
            
            # Security score calculation
            security_score = self._calculate_security_score(
                vulnerabilities, best_practices, defi_security
            )
            analysis_result["security_score"] = security_score
            
            # Additional analysis if contract address provided
            if contract_address:
                deployment_analysis = self._analyze_deployment(contract_address)
                analysis_result["deployment_analysis"] = deployment_analysis
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in Solidity contract analysis: {e}")
            return {"error": str(e)}
    
    def _detect_vulnerabilities(self, contract_code: str) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in Solidity code"""
        vulnerabilities = []
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern_info in patterns:
                matches = list(re.finditer(pattern_info["pattern"], contract_code, re.IGNORECASE | re.MULTILINE))
                
                for match in matches:
                    line_number = contract_code[:match.start()].count('\n') + 1
                    
                    vulnerability = {
                        "type": vuln_type,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "cwe": pattern_info.get("cwe", ""),
                        "line_number": line_number,
                        "code_snippet": self._extract_code_snippet(contract_code, match.start(), match.end()),
                        "recommendation": self._get_vulnerability_recommendation(vuln_type),
                        "confidence": self._calculate_pattern_confidence(pattern_info["pattern"], match.group())
                    }
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_gas_optimization(self, contract_code: str) -> List[Dict[str, Any]]:
        """Analyze gas optimization opportunities"""
        optimizations = []
        
        for opt_type, patterns in self.gas_patterns.items():
            for pattern_info in patterns:
                matches = list(re.finditer(pattern_info["pattern"], contract_code, re.IGNORECASE | re.MULTILINE))
                
                for match in matches:
                    line_number = contract_code[:match.start()].count('\n') + 1
                    
                    optimization = {
                        "type": opt_type,
                        "optimization": pattern_info["optimization"],
                        "gas_saved": pattern_info["gas_saved"],
                        "line_number": line_number,
                        "code_snippet": self._extract_code_snippet(contract_code, match.start(), match.end()),
                        "priority": self._get_optimization_priority(pattern_info["gas_saved"])
                    }
                    
                    optimizations.append(optimization)
        
        return optimizations
    
    def _check_best_practices(self, contract_code: str) -> List[Dict[str, Any]]:
        """Check Solidity best practices compliance"""
        practices = []
        
        for practice_type, patterns in self.best_practices.items():
            for pattern_info in patterns:
                matches = list(re.finditer(pattern_info["pattern"], contract_code, re.IGNORECASE | re.MULTILINE))
                
                for match in matches:
                    line_number = contract_code[:match.start()].count('\n') + 1
                    
                    practice = {
                        "type": practice_type,
                        "recommendation": pattern_info["recommendation"],
                        "severity": pattern_info["severity"],
                        "line_number": line_number,
                        "code_snippet": self._extract_code_snippet(contract_code, match.start(), match.end())
                    }
                    
                    practices.append(practice)
        
        return practices
    
    def _analyze_defi_security(self, contract_code: str) -> List[Dict[str, Any]]:
        """Analyze DeFi-specific security issues"""
        defi_issues = []
        
        for issue_type, patterns in self.defi_patterns.items():
            for pattern_info in patterns:
                matches = list(re.finditer(pattern_info["pattern"], contract_code, re.IGNORECASE | re.MULTILINE))
                
                for match in matches:
                    line_number = contract_code[:match.start()].count('\n') + 1
                    
                    issue = {
                        "type": issue_type,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "recommendation": pattern_info["recommendation"],
                        "line_number": line_number,
                        "code_snippet": self._extract_code_snippet(contract_code, match.start(), match.end())
                    }
                    
                    defi_issues.append(issue)
        
        return defi_issues
    
    def _calculate_contract_metrics(self, contract_code: str) -> Dict[str, Any]:
        """Calculate contract complexity and quality metrics"""
        lines = contract_code.split('\n')
        non_empty_lines = [line for line in lines if line.strip() and not line.strip().startswith('//')]
        
        return {
            "lines_of_code": len(non_empty_lines),
            "function_count": len(re.findall(r'function\s+\w+', contract_code)),
            "modifier_count": len(re.findall(r'modifier\s+\w+', contract_code)),
            "event_count": len(re.findall(r'event\s+\w+', contract_code)),
            "state_variable_count": len(re.findall(r'^\s*(uint|int|bool|address|string|bytes)\s+\w+', contract_code, re.MULTILINE)),
            "external_calls": len(re.findall(r'\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(', contract_code)),
            "cyclomatic_complexity": self._calculate_cyclomatic_complexity(contract_code),
            "inheritance_depth": len(re.findall(r'is\s+\w+', contract_code)),
            "library_usage": len(re.findall(r'using\s+\w+\s+for', contract_code))
        }
    
    def _calculate_cyclomatic_complexity(self, contract_code: str) -> int:
        """Calculate cyclomatic complexity"""
        decision_points = len(re.findall(r'(if|else|for|while|require|assert|\?|\|\||&&)', contract_code))
        functions = len(re.findall(r'function\s+\w+', contract_code))
        return decision_points + functions
    
    def _calculate_security_score(self, vulnerabilities: List[Dict], 
                                best_practices: List[Dict], 
                                defi_security: List[Dict]) -> float:
        """Calculate overall security score (0-100)"""
        base_score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            if vuln["severity"] == "critical":
                base_score -= 25
            elif vuln["severity"] == "high":
                base_score -= 15
            elif vuln["severity"] == "medium":
                base_score -= 8
            elif vuln["severity"] == "low":
                base_score -= 3
        
        # Deduct points for best practice violations
        for practice in best_practices:
            if practice["severity"] == "high":
                base_score -= 10
            elif practice["severity"] == "medium":
                base_score -= 5
            elif practice["severity"] == "low":
                base_score -= 2
        
        # Deduct points for DeFi security issues
        for issue in defi_security:
            if issue["severity"] == "high":
                base_score -= 12
            elif issue["severity"] == "medium":
                base_score -= 6
            elif issue["severity"] == "low":
                base_score -= 3
        
        return max(0.0, base_score)
    
    def _extract_code_snippet(self, code: str, start: int, end: int) -> str:
        """Extract code snippet around match"""
        lines = code.split('\n')
        start_line = code[:start].count('\n')
        end_line = code[:end].count('\n')
        
        # Include context lines
        context_start = max(0, start_line - 1)
        context_end = min(len(lines), end_line + 2)
        
        snippet_lines = lines[context_start:context_end]
        return '\n'.join(snippet_lines)
    
    def _get_vulnerability_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            "reentrancy": "Use the checks-effects-interactions pattern and reentrancy guards",
            "integer_overflow": "Use SafeMath library or Solidity 0.8+ built-in overflow protection",
            "unchecked_call": "Always check return values of external calls",
            "tx_origin": "Use msg.sender instead of tx.origin for authorization",
            "timestamp_dependence": "Avoid using block.timestamp for critical logic",
            "uninitialized_storage": "Initialize storage pointers explicitly",
            "delegatecall": "Validate target contract and use with extreme caution",
            "selfdestruct": "Implement proper access controls for selfdestruct",
            "randomness": "Use secure randomness sources like Chainlink VRF"
        }
        return recommendations.get(vuln_type, "Review and fix the identified issue")
    
    def _calculate_pattern_confidence(self, pattern: str, match: str) -> float:
        """Calculate confidence score for pattern match"""
        # Simple confidence calculation based on pattern specificity
        if len(pattern) > 50:
            return 0.9  # Complex patterns are more specific
        elif len(pattern) > 20:
            return 0.8
        else:
            return 0.7
    
    def _get_optimization_priority(self, gas_saved: str) -> str:
        """Get optimization priority based on gas savings"""
        if "20000" in gas_saved or "slot" in gas_saved:
            return "high"
        elif any(num in gas_saved for num in ["100", "200", "50"]):
            return "medium"
        else:
            return "low"
    
    def _analyze_deployment(self, contract_address: str) -> Dict[str, Any]:
        """Analyze deployed contract (mock implementation)"""
        # In a real implementation, this would interact with blockchain APIs
        return {
            "contract_address": contract_address,
            "deployment_date": "2024-01-01T00:00:00Z",
            "compiler_version": "0.8.19",
            "optimization_enabled": True,
            "verification_status": "verified",
            "proxy_pattern": self._detect_proxy_pattern(contract_address),
            "upgrade_mechanism": "transparent_proxy"
        }
    
    def _detect_proxy_pattern(self, contract_address: str) -> str:
        """Detect proxy pattern used (mock implementation)"""
        # Mock detection logic
        patterns = ["transparent", "uups", "beacon", "diamond", "none"]
        return patterns[len(contract_address) % len(patterns)]
    
    def analyze_gas_optimization(self, contract_code: str) -> Dict[str, Any]:
        """Dedicated gas optimization analysis"""
        try:
            optimizations = self._analyze_gas_optimization(contract_code)
            
            # Calculate potential gas savings
            total_savings = self._calculate_total_gas_savings(optimizations)
            
            # Prioritize optimizations
            prioritized = self._prioritize_optimizations(optimizations)
            
            return {
                "optimizations": optimizations,
                "total_potential_savings": total_savings,
                "prioritized_optimizations": prioritized,
                "optimization_summary": self._generate_optimization_summary(optimizations),
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error in gas optimization analysis: {e}")
            return {"error": str(e)}
    
    def _calculate_total_gas_savings(self, optimizations: List[Dict]) -> Dict[str, Any]:
        """Calculate total potential gas savings"""
        high_priority = len([opt for opt in optimizations if opt.get("priority") == "high"])
        medium_priority = len([opt for opt in optimizations if opt.get("priority") == "medium"])
        low_priority = len([opt for opt in optimizations if opt.get("priority") == "low"])
        
        return {
            "high_impact_optimizations": high_priority,
            "medium_impact_optimizations": medium_priority,
            "low_impact_optimizations": low_priority,
            "estimated_total_savings": f"{high_priority * 15000 + medium_priority * 5000 + low_priority * 1000} gas",
            "deployment_cost_reduction": f"{(high_priority + medium_priority) * 2}%"
        }
    
    def _prioritize_optimizations(self, optimizations: List[Dict]) -> List[Dict]:
        """Prioritize optimizations by impact"""
        priority_order = {"high": 3, "medium": 2, "low": 1}
        
        return sorted(optimizations, 
                     key=lambda x: priority_order.get(x.get("priority", "low"), 0), 
                     reverse=True)
    
    def _generate_optimization_summary(self, optimizations: List[Dict]) -> Dict[str, Any]:
        """Generate optimization summary"""
        categories = {}
        for opt in optimizations:
            category = opt.get("type", "unknown")
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        return {
            "total_optimizations": len(optimizations),
            "categories": categories,
            "top_category": max(categories.items(), key=lambda x: x[1])[0] if categories else "none",
            "optimization_score": min(100, len(optimizations) * 5)
        }

