"""
DeFi Security Analyzer
Advanced analysis of DeFi protocols for security vulnerabilities and risks
"""

import re
import json
import math
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging

class DeFiSecurityAnalyzer:
    """
    Advanced DeFi Security Analyzer
    
    Features:
    - Rug pull detection
    - Flash loan attack analysis
    - Liquidity manipulation detection
    - Price oracle vulnerabilities
    - Governance attack vectors
    - MEV vulnerability assessment
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Rug pull indicators
        self.rug_pull_patterns = self._load_rug_pull_patterns()
        
        # Flash loan attack patterns
        self.flash_loan_patterns = self._load_flash_loan_patterns()
        
        # DeFi protocol risks
        self.protocol_risks = self._load_protocol_risks()
        
        # Oracle manipulation patterns
        self.oracle_patterns = self._load_oracle_patterns()
        
        # MEV vulnerability patterns
        self.mev_patterns = self._load_mev_patterns()
        
        self.logger.info("DeFiSecurityAnalyzer initialized successfully")
    
    def _load_rug_pull_patterns(self) -> Dict[str, List[Dict]]:
        """Load rug pull detection patterns"""
        return {
            "liquidity_removal": [
                {
                    "pattern": r"removeLiquidity.*100.*percent",
                    "risk_level": "critical",
                    "description": "Large liquidity removal detected",
                    "indicator": "massive_liquidity_drain"
                },
                {
                    "pattern": r"transfer.*owner.*balance",
                    "risk_level": "high",
                    "description": "Owner transferring large amounts",
                    "indicator": "owner_dump"
                }
            ],
            "ownership_concentration": [
                {
                    "threshold": 0.5,  # 50% ownership
                    "risk_level": "high",
                    "description": "High ownership concentration",
                    "indicator": "centralized_control"
                }
            ],
            "trading_restrictions": [
                {
                    "pattern": r"onlyOwner.*transfer",
                    "risk_level": "critical",
                    "description": "Owner-only transfer restrictions",
                    "indicator": "transfer_restrictions"
                },
                {
                    "pattern": r"blacklist.*mapping",
                    "risk_level": "medium",
                    "description": "Blacklist functionality present",
                    "indicator": "blacklist_mechanism"
                }
            ],
            "honeypot_indicators": [
                {
                    "pattern": r"require.*balanceOf.*sender.*>.*amount",
                    "risk_level": "high",
                    "description": "Potential honeypot - balance check manipulation",
                    "indicator": "balance_manipulation"
                },
                {
                    "pattern": r"if.*msg\.sender.*!=.*owner.*revert",
                    "risk_level": "critical",
                    "description": "Only owner can sell - honeypot indicator",
                    "indicator": "sell_restriction"
                }
            ]
        }
    
    def _load_flash_loan_patterns(self) -> Dict[str, List[Dict]]:
        """Load flash loan attack patterns"""
        return {
            "price_manipulation": [
                {
                    "pattern": r"flashLoan.*swap.*getPrice",
                    "risk_level": "critical",
                    "description": "Flash loan used for price manipulation",
                    "attack_type": "oracle_manipulation"
                },
                {
                    "pattern": r"borrow.*large.*amount.*single.*block",
                    "risk_level": "high",
                    "description": "Large borrowing in single transaction",
                    "attack_type": "liquidity_drain"
                }
            ],
            "arbitrage_exploitation": [
                {
                    "pattern": r"flashLoan.*arbitrage.*profit",
                    "risk_level": "medium",
                    "description": "Flash loan arbitrage - monitor for exploitation",
                    "attack_type": "arbitrage_abuse"
                }
            ],
            "governance_attacks": [
                {
                    "pattern": r"flashLoan.*vote.*proposal",
                    "risk_level": "critical",
                    "description": "Flash loan used for governance manipulation",
                    "attack_type": "governance_attack"
                }
            ]
        }
    
    def _load_protocol_risks(self) -> Dict[str, Dict]:
        """Load DeFi protocol risk categories"""
        return {
            "smart_contract_risk": {
                "weight": 0.3,
                "factors": ["code_complexity", "audit_status", "upgrade_mechanism"]
            },
            "liquidity_risk": {
                "weight": 0.25,
                "factors": ["total_liquidity", "liquidity_concentration", "withdrawal_limits"]
            },
            "oracle_risk": {
                "weight": 0.2,
                "factors": ["oracle_type", "price_feeds", "manipulation_resistance"]
            },
            "governance_risk": {
                "weight": 0.15,
                "factors": ["token_distribution", "voting_mechanism", "timelock_delays"]
            },
            "economic_risk": {
                "weight": 0.1,
                "factors": ["tokenomics", "incentive_alignment", "sustainability"]
            }
        }
    
    def _load_oracle_patterns(self) -> Dict[str, List[Dict]]:
        """Load oracle manipulation patterns"""
        return {
            "single_source_oracle": [
                {
                    "pattern": r"getPrice.*single.*source",
                    "risk_level": "high",
                    "description": "Single oracle source - manipulation risk",
                    "mitigation": "Use multiple oracle sources"
                }
            ],
            "dex_price_oracle": [
                {
                    "pattern": r"getAmountsOut.*uniswap.*price",
                    "risk_level": "critical",
                    "description": "Using DEX as price oracle - highly manipulable",
                    "mitigation": "Use time-weighted average price (TWAP)"
                }
            ],
            "no_price_validation": [
                {
                    "pattern": r"getPrice.*(?!.*validate|.*check|.*verify)",
                    "risk_level": "medium",
                    "description": "Price used without validation",
                    "mitigation": "Implement price sanity checks"
                }
            ]
        }
    
    def _load_mev_patterns(self) -> Dict[str, List[Dict]]:
        """Load MEV vulnerability patterns"""
        return {
            "frontrunning_vulnerable": [
                {
                    "pattern": r"swap.*public.*no.*protection",
                    "risk_level": "medium",
                    "description": "Swap function vulnerable to frontrunning",
                    "protection": "Use commit-reveal or private mempool"
                }
            ],
            "sandwich_attack": [
                {
                    "pattern": r"large.*swap.*no.*slippage.*protection",
                    "risk_level": "high",
                    "description": "Large swaps without slippage protection",
                    "protection": "Implement maximum slippage limits"
                }
            ],
            "liquidation_mev": [
                {
                    "pattern": r"liquidate.*public.*immediate",
                    "risk_level": "low",
                    "description": "Liquidation function may be MEV extractable",
                    "protection": "Consider Dutch auction liquidations"
                }
            ]
        }
    
    def analyze_protocol(self, protocol_address: str, protocol_type: str = "unknown", 
                        analysis_depth: str = "comprehensive") -> Dict[str, Any]:
        """Analyze DeFi protocol for security risks"""
        try:
            analysis_result = {
                "protocol_address": protocol_address,
                "protocol_type": protocol_type,
                "analysis_depth": analysis_depth,
                "risk_assessment": {},
                "vulnerabilities": [],
                "recommendations": [],
                "overall_risk_score": 0,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
            # Mock contract code retrieval (in real implementation, would fetch from blockchain)
            contract_code = self._fetch_contract_code(protocol_address)
            
            # Risk assessment
            risk_assessment = self._assess_protocol_risks(contract_code, protocol_type)
            analysis_result["risk_assessment"] = risk_assessment
            
            # Vulnerability detection
            vulnerabilities = self._detect_defi_vulnerabilities(contract_code)
            analysis_result["vulnerabilities"] = vulnerabilities
            
            # Oracle analysis
            oracle_analysis = self._analyze_oracle_security(contract_code)
            analysis_result["oracle_analysis"] = oracle_analysis
            
            # MEV vulnerability assessment
            mev_analysis = self._analyze_mev_vulnerabilities(contract_code)
            analysis_result["mev_analysis"] = mev_analysis
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                vulnerabilities, oracle_analysis, mev_analysis
            )
            analysis_result["recommendations"] = recommendations
            
            # Calculate overall risk score
            overall_risk = self._calculate_overall_risk_score(
                risk_assessment, vulnerabilities, oracle_analysis, mev_analysis
            )
            analysis_result["overall_risk_score"] = overall_risk
            
            # Protocol-specific analysis
            if protocol_type in ["dex", "lending", "yield_farming", "derivatives"]:
                specific_analysis = self._analyze_protocol_specific_risks(
                    contract_code, protocol_type
                )
                analysis_result[f"{protocol_type}_specific_analysis"] = specific_analysis
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in DeFi protocol analysis: {e}")
            return {"error": str(e)}
    
    def detect_rug_pull(self, token_address: str, blockchain: str = "ethereum") -> Dict[str, Any]:
        """Detect potential rug pull indicators"""
        try:
            rug_pull_analysis = {
                "token_address": token_address,
                "blockchain": blockchain,
                "risk_indicators": [],
                "risk_level": "low",
                "confidence_score": 0,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
            # Mock token data (in real implementation, would fetch from blockchain APIs)
            token_data = self._fetch_token_data(token_address, blockchain)
            contract_code = token_data.get("contract_code", "")
            
            # Check for rug pull patterns
            for category, patterns in self.rug_pull_patterns.items():
                for pattern_info in patterns:
                    if "pattern" in pattern_info:
                        if re.search(pattern_info["pattern"], contract_code, re.IGNORECASE):
                            rug_pull_analysis["risk_indicators"].append({
                                "category": category,
                                "indicator": pattern_info["indicator"],
                                "risk_level": pattern_info["risk_level"],
                                "description": pattern_info["description"]
                            })
            
            # Check ownership concentration
            ownership_analysis = self._analyze_ownership_concentration(token_data)
            if ownership_analysis["concentration_risk"] > 0.5:
                rug_pull_analysis["risk_indicators"].append({
                    "category": "ownership_concentration",
                    "indicator": "high_concentration",
                    "risk_level": "high",
                    "description": f"Top holders control {ownership_analysis['concentration_risk']*100:.1f}% of supply"
                })
            
            # Check liquidity metrics
            liquidity_analysis = self._analyze_liquidity_metrics(token_data)
            if liquidity_analysis["liquidity_risk"] > 0.7:
                rug_pull_analysis["risk_indicators"].append({
                    "category": "liquidity_risk",
                    "indicator": "low_liquidity",
                    "risk_level": "medium",
                    "description": "Low liquidity makes token vulnerable to manipulation"
                })
            
            # Check trading patterns
            trading_analysis = self._analyze_trading_patterns(token_data)
            for anomaly in trading_analysis["anomalies"]:
                rug_pull_analysis["risk_indicators"].append({
                    "category": "trading_anomaly",
                    "indicator": anomaly["type"],
                    "risk_level": anomaly["severity"],
                    "description": anomaly["description"]
                })
            
            # Calculate overall risk level and confidence
            risk_level, confidence = self._calculate_rug_pull_risk(
                rug_pull_analysis["risk_indicators"]
            )
            rug_pull_analysis["risk_level"] = risk_level
            rug_pull_analysis["confidence_score"] = confidence
            
            # Add mitigation recommendations
            rug_pull_analysis["mitigation_recommendations"] = self._get_rug_pull_mitigations(
                rug_pull_analysis["risk_indicators"]
            )
            
            return rug_pull_analysis
            
        except Exception as e:
            self.logger.error(f"Error in rug pull detection: {e}")
            return {"error": str(e)}
    
    def _fetch_contract_code(self, address: str) -> str:
        """Mock function to fetch contract code"""
        # In real implementation, would use blockchain APIs like Etherscan
        mock_contracts = {
            "uniswap": """
                contract UniswapV2Pair {
                    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
                        require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');
                        // ... swap logic
                    }
                    
                    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
                        _reserve0 = reserve0;
                        _reserve1 = reserve1;
                        _blockTimestampLast = blockTimestampLast;
                    }
                }
            """,
            "suspicious": """
                contract SuspiciousToken {
                    mapping(address => bool) public blacklist;
                    address public owner;
                    
                    modifier onlyOwner() {
                        require(msg.sender == owner, "Not owner");
                        _;
                    }
                    
                    function transfer(address to, uint256 amount) public returns (bool) {
                        require(!blacklist[msg.sender], "Blacklisted");
                        if (msg.sender != owner) {
                            require(balanceOf[msg.sender] > amount * 2, "Insufficient balance");
                        }
                        // ... transfer logic
                    }
                    
                    function removeLiquidity() external onlyOwner {
                        // Owner can remove all liquidity
                    }
                }
            """
        }
        
        # Simple address-based mock selection
        if "suspicious" in address.lower():
            return mock_contracts["suspicious"]
        else:
            return mock_contracts["uniswap"]
    
    def _fetch_token_data(self, address: str, blockchain: str) -> Dict[str, Any]:
        """Mock function to fetch token data"""
        # Mock token data
        return {
            "contract_code": self._fetch_contract_code(address),
            "total_supply": 1000000,
            "circulating_supply": 800000,
            "holder_count": 1500,
            "top_holders": [
                {"address": "0x123...", "balance": 300000, "percentage": 30.0},
                {"address": "0x456...", "balance": 200000, "percentage": 20.0},
                {"address": "0x789...", "balance": 150000, "percentage": 15.0}
            ],
            "liquidity_pools": [
                {"dex": "uniswap", "liquidity_usd": 500000, "volume_24h": 100000}
            ],
            "trading_history": {
                "volume_24h": 250000,
                "price_change_24h": -5.2,
                "transactions_24h": 450
            }
        }
    
    def _assess_protocol_risks(self, contract_code: str, protocol_type: str) -> Dict[str, Any]:
        """Assess various protocol risks"""
        risk_assessment = {}
        
        for risk_category, risk_info in self.protocol_risks.items():
            risk_score = 0
            
            if risk_category == "smart_contract_risk":
                risk_score = self._assess_smart_contract_risk(contract_code)
            elif risk_category == "liquidity_risk":
                risk_score = self._assess_liquidity_risk(contract_code)
            elif risk_category == "oracle_risk":
                risk_score = self._assess_oracle_risk(contract_code)
            elif risk_category == "governance_risk":
                risk_score = self._assess_governance_risk(contract_code)
            elif risk_category == "economic_risk":
                risk_score = self._assess_economic_risk(contract_code, protocol_type)
            
            risk_assessment[risk_category] = {
                "score": risk_score,
                "weight": risk_info["weight"],
                "weighted_score": risk_score * risk_info["weight"],
                "factors": risk_info["factors"]
            }
        
        return risk_assessment
    
    def _detect_defi_vulnerabilities(self, contract_code: str) -> List[Dict[str, Any]]:
        """Detect DeFi-specific vulnerabilities"""
        vulnerabilities = []
        
        # Check flash loan patterns
        for category, patterns in self.flash_loan_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], contract_code, re.IGNORECASE):
                    vulnerabilities.append({
                        "category": "flash_loan_vulnerability",
                        "type": pattern_info["attack_type"],
                        "risk_level": pattern_info["risk_level"],
                        "description": pattern_info["description"],
                        "mitigation": self._get_flash_loan_mitigation(pattern_info["attack_type"])
                    })
        
        # Check for common DeFi vulnerabilities
        defi_vulns = [
            {
                "pattern": r"transfer.*without.*approval",
                "type": "unauthorized_transfer",
                "risk_level": "critical",
                "description": "Transfers without proper approval checks"
            },
            {
                "pattern": r"price.*manipulation.*vulnerable",
                "type": "price_manipulation",
                "risk_level": "high",
                "description": "Price calculation vulnerable to manipulation"
            },
            {
                "pattern": r"reentrancy.*vulnerable",
                "type": "reentrancy",
                "risk_level": "critical",
                "description": "Reentrancy vulnerability in DeFi functions"
            }
        ]
        
        for vuln_info in defi_vulns:
            if re.search(vuln_info["pattern"], contract_code, re.IGNORECASE):
                vulnerabilities.append({
                    "category": "defi_vulnerability",
                    "type": vuln_info["type"],
                    "risk_level": vuln_info["risk_level"],
                    "description": vuln_info["description"]
                })
        
        return vulnerabilities
    
    def _analyze_oracle_security(self, contract_code: str) -> Dict[str, Any]:
        """Analyze oracle security implementation"""
        oracle_analysis = {
            "oracle_type": "unknown",
            "vulnerabilities": [],
            "security_score": 0,
            "recommendations": []
        }
        
        # Detect oracle type
        if "chainlink" in contract_code.lower():
            oracle_analysis["oracle_type"] = "chainlink"
            oracle_analysis["security_score"] += 30
        elif "uniswap" in contract_code.lower() and "getamountsout" in contract_code.lower():
            oracle_analysis["oracle_type"] = "dex_based"
            oracle_analysis["security_score"] -= 20
        elif "twap" in contract_code.lower():
            oracle_analysis["oracle_type"] = "twap"
            oracle_analysis["security_score"] += 15
        
        # Check for oracle vulnerabilities
        for category, patterns in self.oracle_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], contract_code, re.IGNORECASE):
                    oracle_analysis["vulnerabilities"].append({
                        "type": category,
                        "risk_level": pattern_info["risk_level"],
                        "description": pattern_info["description"],
                        "mitigation": pattern_info["mitigation"]
                    })
                    
                    # Adjust security score
                    if pattern_info["risk_level"] == "critical":
                        oracle_analysis["security_score"] -= 25
                    elif pattern_info["risk_level"] == "high":
                        oracle_analysis["security_score"] -= 15
                    elif pattern_info["risk_level"] == "medium":
                        oracle_analysis["security_score"] -= 8
        
        # Generate recommendations
        oracle_analysis["recommendations"] = self._generate_oracle_recommendations(
            oracle_analysis["oracle_type"], oracle_analysis["vulnerabilities"]
        )
        
        # Normalize security score
        oracle_analysis["security_score"] = max(0, min(100, oracle_analysis["security_score"] + 50))
        
        return oracle_analysis
    
    def _analyze_mev_vulnerabilities(self, contract_code: str) -> Dict[str, Any]:
        """Analyze MEV vulnerability exposure"""
        mev_analysis = {
            "vulnerabilities": [],
            "mev_risk_score": 0,
            "protection_mechanisms": [],
            "recommendations": []
        }
        
        # Check for MEV vulnerabilities
        for category, patterns in self.mev_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], contract_code, re.IGNORECASE):
                    mev_analysis["vulnerabilities"].append({
                        "type": category,
                        "risk_level": pattern_info["risk_level"],
                        "description": pattern_info["description"],
                        "protection": pattern_info["protection"]
                    })
                    
                    # Calculate MEV risk score
                    if pattern_info["risk_level"] == "high":
                        mev_analysis["mev_risk_score"] += 30
                    elif pattern_info["risk_level"] == "medium":
                        mev_analysis["mev_risk_score"] += 15
                    elif pattern_info["risk_level"] == "low":
                        mev_analysis["mev_risk_score"] += 5
        
        # Check for existing protection mechanisms
        protections = [
            {"pattern": r"commit.*reveal", "mechanism": "commit_reveal_scheme"},
            {"pattern": r"private.*mempool", "mechanism": "private_mempool"},
            {"pattern": r"slippage.*protection", "mechanism": "slippage_protection"},
            {"pattern": r"time.*delay", "mechanism": "time_delays"}
        ]
        
        for protection in protections:
            if re.search(protection["pattern"], contract_code, re.IGNORECASE):
                mev_analysis["protection_mechanisms"].append(protection["mechanism"])
                mev_analysis["mev_risk_score"] -= 10
        
        # Generate MEV protection recommendations
        mev_analysis["recommendations"] = self._generate_mev_recommendations(
            mev_analysis["vulnerabilities"], mev_analysis["protection_mechanisms"]
        )
        
        # Normalize MEV risk score
        mev_analysis["mev_risk_score"] = max(0, min(100, mev_analysis["mev_risk_score"]))
        
        return mev_analysis
    
    def _analyze_ownership_concentration(self, token_data: Dict) -> Dict[str, Any]:
        """Analyze token ownership concentration"""
        top_holders = token_data.get("top_holders", [])
        total_supply = token_data.get("total_supply", 1)
        
        # Calculate concentration metrics
        top_5_concentration = sum(holder["balance"] for holder in top_holders[:5]) / total_supply
        top_10_concentration = sum(holder["balance"] for holder in top_holders[:10]) / total_supply
        
        return {
            "concentration_risk": top_5_concentration,
            "top_5_concentration": top_5_concentration,
            "top_10_concentration": top_10_concentration,
            "gini_coefficient": self._calculate_gini_coefficient(top_holders),
            "risk_level": "high" if top_5_concentration > 0.5 else "medium" if top_5_concentration > 0.3 else "low"
        }
    
    def _analyze_liquidity_metrics(self, token_data: Dict) -> Dict[str, Any]:
        """Analyze token liquidity metrics"""
        liquidity_pools = token_data.get("liquidity_pools", [])
        trading_history = token_data.get("trading_history", {})
        
        total_liquidity = sum(pool["liquidity_usd"] for pool in liquidity_pools)
        total_volume = trading_history.get("volume_24h", 0)
        
        # Calculate liquidity risk
        liquidity_ratio = total_volume / max(total_liquidity, 1)
        
        return {
            "total_liquidity_usd": total_liquidity,
            "volume_to_liquidity_ratio": liquidity_ratio,
            "liquidity_risk": 1 - min(1, total_liquidity / 1000000),  # Risk decreases with liquidity
            "pool_count": len(liquidity_pools),
            "largest_pool_dominance": max(pool["liquidity_usd"] for pool in liquidity_pools) / max(total_liquidity, 1) if liquidity_pools else 0
        }
    
    def _analyze_trading_patterns(self, token_data: Dict) -> Dict[str, Any]:
        """Analyze trading patterns for anomalies"""
        trading_history = token_data.get("trading_history", {})
        
        anomalies = []
        
        # Check for unusual price movements
        price_change = trading_history.get("price_change_24h", 0)
        if abs(price_change) > 50:
            anomalies.append({
                "type": "extreme_price_movement",
                "severity": "high",
                "description": f"Extreme price change: {price_change:.1f}% in 24h"
            })
        
        # Check volume anomalies
        volume_24h = trading_history.get("volume_24h", 0)
        transactions_24h = trading_history.get("transactions_24h", 1)
        avg_transaction_size = volume_24h / transactions_24h
        
        if avg_transaction_size > 10000:  # Large average transaction size
            anomalies.append({
                "type": "large_transaction_pattern",
                "severity": "medium",
                "description": f"Large average transaction size: ${avg_transaction_size:.0f}"
            })
        
        return {
            "anomalies": anomalies,
            "trading_score": max(0, 100 - len(anomalies) * 20)
        }
    
    def _calculate_gini_coefficient(self, holders: List[Dict]) -> float:
        """Calculate Gini coefficient for wealth distribution"""
        if not holders:
            return 0
        
        balances = sorted([holder["balance"] for holder in holders])
        n = len(balances)
        
        if n == 0:
            return 0
        
        # Calculate Gini coefficient
        cumsum = sum((i + 1) * balance for i, balance in enumerate(balances))
        total = sum(balances)
        
        if total == 0:
            return 0
        
        gini = (2 * cumsum) / (n * total) - (n + 1) / n
        return gini
    
    def _calculate_rug_pull_risk(self, risk_indicators: List[Dict]) -> Tuple[str, float]:
        """Calculate overall rug pull risk level and confidence"""
        critical_count = len([r for r in risk_indicators if r["risk_level"] == "critical"])
        high_count = len([r for r in risk_indicators if r["risk_level"] == "high"])
        medium_count = len([r for r in risk_indicators if r["risk_level"] == "medium"])
        
        # Calculate risk score
        risk_score = critical_count * 40 + high_count * 25 + medium_count * 10
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Calculate confidence (based on number of indicators)
        confidence = min(0.95, len(risk_indicators) * 0.15 + 0.3)
        
        return risk_level, confidence
    
    def _get_rug_pull_mitigations(self, risk_indicators: List[Dict]) -> List[str]:
        """Get mitigation recommendations for rug pull risks"""
        mitigations = []
        
        indicator_types = [indicator["indicator"] for indicator in risk_indicators]
        
        if "high_concentration" in indicator_types:
            mitigations.append("Diversify token holdings across more addresses")
        
        if "transfer_restrictions" in indicator_types:
            mitigations.append("Remove or reduce transfer restrictions")
        
        if "blacklist_mechanism" in indicator_types:
            mitigations.append("Implement transparent blacklist criteria")
        
        if "sell_restriction" in indicator_types:
            mitigations.append("Allow all holders to sell tokens freely")
        
        if "low_liquidity" in indicator_types:
            mitigations.append("Increase liquidity pool depth")
        
        return mitigations
    
    def _assess_smart_contract_risk(self, contract_code: str) -> float:
        """Assess smart contract risk factors"""
        risk_score = 50  # Base score
        
        # Code complexity
        lines = len(contract_code.split('\n'))
        if lines > 1000:
            risk_score += 20
        elif lines > 500:
            risk_score += 10
        
        # External calls
        external_calls = len(re.findall(r'\.call\(|\.delegatecall\(', contract_code))
        risk_score += external_calls * 5
        
        # Upgrade mechanisms
        if "upgrade" in contract_code.lower():
            risk_score += 15
        
        return min(100, risk_score)
    
    def _assess_liquidity_risk(self, contract_code: str) -> float:
        """Assess liquidity-related risks"""
        risk_score = 30  # Base score
        
        # Check for liquidity locks
        if "lock" in contract_code.lower() and "liquidity" in contract_code.lower():
            risk_score -= 20
        
        # Check for withdrawal limits
        if "withdraw" in contract_code.lower() and "limit" in contract_code.lower():
            risk_score -= 10
        
        return max(0, min(100, risk_score))
    
    def _assess_oracle_risk(self, contract_code: str) -> float:
        """Assess oracle-related risks"""
        risk_score = 40  # Base score
        
        # Chainlink usage reduces risk
        if "chainlink" in contract_code.lower():
            risk_score -= 25
        
        # DEX price usage increases risk
        if "getamountsout" in contract_code.lower():
            risk_score += 30
        
        # TWAP usage reduces risk
        if "twap" in contract_code.lower():
            risk_score -= 15
        
        return max(0, min(100, risk_score))
    
    def _assess_governance_risk(self, contract_code: str) -> float:
        """Assess governance-related risks"""
        risk_score = 35  # Base score
        
        # Timelock reduces risk
        if "timelock" in contract_code.lower():
            risk_score -= 20
        
        # Multisig reduces risk
        if "multisig" in contract_code.lower():
            risk_score -= 15
        
        # Owner controls increase risk
        owner_controls = len(re.findall(r'onlyOwner', contract_code))
        risk_score += owner_controls * 5
        
        return max(0, min(100, risk_score))
    
    def _assess_economic_risk(self, contract_code: str, protocol_type: str) -> float:
        """Assess economic model risks"""
        risk_score = 45  # Base score
        
        # Protocol-specific adjustments
        if protocol_type == "yield_farming":
            risk_score += 15  # Higher economic risk
        elif protocol_type == "lending":
            risk_score += 10
        elif protocol_type == "dex":
            risk_score -= 5
        
        # Inflation mechanisms
        if "mint" in contract_code.lower() and "unlimited" in contract_code.lower():
            risk_score += 20
        
        return max(0, min(100, risk_score))
    
    def _generate_recommendations(self, vulnerabilities: List[Dict], 
                                oracle_analysis: Dict, mev_analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Vulnerability-based recommendations
        vuln_types = [v["type"] for v in vulnerabilities]
        if "price_manipulation" in vuln_types:
            recommendations.append("Implement robust price oracle mechanisms")
        if "reentrancy" in vuln_types:
            recommendations.append("Add reentrancy guards to all external functions")
        if "unauthorized_transfer" in vuln_types:
            recommendations.append("Implement proper authorization checks")
        
        # Oracle recommendations
        if oracle_analysis["oracle_type"] == "dex_based":
            recommendations.append("Replace DEX-based pricing with Chainlink oracles")
        if oracle_analysis["security_score"] < 50:
            recommendations.append("Improve oracle security implementation")
        
        # MEV recommendations
        if mev_analysis["mev_risk_score"] > 50:
            recommendations.append("Implement MEV protection mechanisms")
        
        return recommendations
    
    def _calculate_overall_risk_score(self, risk_assessment: Dict, vulnerabilities: List[Dict],
                                    oracle_analysis: Dict, mev_analysis: Dict) -> float:
        """Calculate overall protocol risk score"""
        # Weighted risk assessment score
        weighted_score = sum(
            assessment["weighted_score"] for assessment in risk_assessment.values()
        )
        
        # Vulnerability penalty
        vuln_penalty = len(vulnerabilities) * 5
        
        # Oracle risk adjustment
        oracle_penalty = (100 - oracle_analysis["security_score"]) * 0.2
        
        # MEV risk adjustment
        mev_penalty = mev_analysis["mev_risk_score"] * 0.15
        
        # Calculate final score (0-100, lower is better)
        final_score = weighted_score + vuln_penalty + oracle_penalty + mev_penalty
        
        return min(100, max(0, final_score))
    
    def _analyze_protocol_specific_risks(self, contract_code: str, protocol_type: str) -> Dict[str, Any]:
        """Analyze protocol-specific risks"""
        if protocol_type == "dex":
            return self._analyze_dex_risks(contract_code)
        elif protocol_type == "lending":
            return self._analyze_lending_risks(contract_code)
        elif protocol_type == "yield_farming":
            return self._analyze_yield_farming_risks(contract_code)
        elif protocol_type == "derivatives":
            return self._analyze_derivatives_risks(contract_code)
        else:
            return {"analysis": "Protocol type not specifically supported"}
    
    def _analyze_dex_risks(self, contract_code: str) -> Dict[str, Any]:
        """Analyze DEX-specific risks"""
        return {
            "impermanent_loss_risk": "medium",
            "slippage_protection": "swap" in contract_code.lower() and "slippage" in contract_code.lower(),
            "fee_mechanism": "fee" in contract_code.lower(),
            "liquidity_incentives": "reward" in contract_code.lower() or "incentive" in contract_code.lower()
        }
    
    def _analyze_lending_risks(self, contract_code: str) -> Dict[str, Any]:
        """Analyze lending protocol risks"""
        return {
            "liquidation_mechanism": "liquidate" in contract_code.lower(),
            "collateral_requirements": "collateral" in contract_code.lower(),
            "interest_rate_model": "interest" in contract_code.lower() and "rate" in contract_code.lower(),
            "bad_debt_protection": "insurance" in contract_code.lower() or "reserve" in contract_code.lower()
        }
    
    def _analyze_yield_farming_risks(self, contract_code: str) -> Dict[str, Any]:
        """Analyze yield farming risks"""
        return {
            "reward_sustainability": "sustainable" in contract_code.lower(),
            "token_emission_rate": "emission" in contract_code.lower() or "mint" in contract_code.lower(),
            "pool_migration_risk": "migrate" in contract_code.lower(),
            "governance_token_risk": "governance" in contract_code.lower()
        }
    
    def _analyze_derivatives_risks(self, contract_code: str) -> Dict[str, Any]:
        """Analyze derivatives protocol risks"""
        return {
            "margin_requirements": "margin" in contract_code.lower(),
            "liquidation_cascade_risk": "cascade" in contract_code.lower(),
            "funding_rate_mechanism": "funding" in contract_code.lower(),
            "settlement_mechanism": "settle" in contract_code.lower()
        }
    
    def _get_flash_loan_mitigation(self, attack_type: str) -> str:
        """Get mitigation for flash loan attack type"""
        mitigations = {
            "oracle_manipulation": "Use time-weighted average prices and multiple oracle sources",
            "liquidity_drain": "Implement borrowing limits and circuit breakers",
            "arbitrage_abuse": "Add transaction fees and minimum holding periods",
            "governance_attack": "Implement voting delays and snapshot mechanisms"
        }
        return mitigations.get(attack_type, "Implement general flash loan protections")
    
    def _generate_oracle_recommendations(self, oracle_type: str, vulnerabilities: List[Dict]) -> List[str]:
        """Generate oracle-specific recommendations"""
        recommendations = []
        
        if oracle_type == "dex_based":
            recommendations.append("Migrate to Chainlink price feeds")
            recommendations.append("Implement TWAP as fallback mechanism")
        elif oracle_type == "unknown":
            recommendations.append("Implement proper price oracle system")
        
        for vuln in vulnerabilities:
            if vuln["type"] == "single_source_oracle":
                recommendations.append("Use multiple oracle sources for price validation")
            elif vuln["type"] == "no_price_validation":
                recommendations.append("Add price sanity checks and circuit breakers")
        
        return recommendations
    
    def _generate_mev_recommendations(self, vulnerabilities: List[Dict], 
                                    protection_mechanisms: List[str]) -> List[str]:
        """Generate MEV protection recommendations"""
        recommendations = []
        
        if "commit_reveal_scheme" not in protection_mechanisms:
            recommendations.append("Implement commit-reveal scheme for sensitive operations")
        
        if "slippage_protection" not in protection_mechanisms:
            recommendations.append("Add slippage protection to all swap functions")
        
        for vuln in vulnerabilities:
            if vuln["type"] == "frontrunning_vulnerable":
                recommendations.append("Use private mempool or batch transactions")
            elif vuln["type"] == "sandwich_attack":
                recommendations.append("Implement maximum slippage limits")
        
        return recommendations
    
    def generate_audit_report(self, protocol_address: str, audit_scope: str = "comprehensive") -> Dict[str, Any]:
        """Generate comprehensive DeFi audit report"""
        try:
            # Perform comprehensive analysis
            protocol_analysis = self.analyze_protocol(protocol_address, analysis_depth=audit_scope)
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(protocol_analysis)
            
            # Generate detailed findings
            detailed_findings = self._generate_detailed_findings(protocol_analysis)
            
            # Generate recommendations
            recommendations = self._generate_audit_recommendations(protocol_analysis)
            
            audit_report = {
                "audit_metadata": {
                    "protocol_address": protocol_address,
                    "audit_scope": audit_scope,
                    "audit_date": datetime.utcnow().isoformat(),
                    "auditor": "AI Guardian DeFi Security Analyzer v4.0.0"
                },
                "executive_summary": executive_summary,
                "detailed_findings": detailed_findings,
                "recommendations": recommendations,
                "risk_matrix": self._generate_risk_matrix(protocol_analysis),
                "compliance_assessment": self._assess_compliance(protocol_analysis),
                "conclusion": self._generate_audit_conclusion(protocol_analysis)
            }
            
            return audit_report
            
        except Exception as e:
            self.logger.error(f"Error generating audit report: {e}")
            return {"error": str(e)}
    
    def _generate_executive_summary(self, analysis: Dict) -> Dict[str, Any]:
        """Generate executive summary for audit report"""
        overall_risk = analysis.get("overall_risk_score", 0)
        vulnerabilities = analysis.get("vulnerabilities", [])
        
        risk_level = "low"
        if overall_risk > 70:
            risk_level = "critical"
        elif overall_risk > 50:
            risk_level = "high"
        elif overall_risk > 30:
            risk_level = "medium"
        
        return {
            "overall_risk_level": risk_level,
            "overall_risk_score": overall_risk,
            "critical_findings": len([v for v in vulnerabilities if v.get("risk_level") == "critical"]),
            "high_findings": len([v for v in vulnerabilities if v.get("risk_level") == "high"]),
            "medium_findings": len([v for v in vulnerabilities if v.get("risk_level") == "medium"]),
            "key_recommendations": analysis.get("recommendations", [])[:3]
        }
    
    def _generate_detailed_findings(self, analysis: Dict) -> List[Dict[str, Any]]:
        """Generate detailed findings section"""
        findings = []
        
        # Add vulnerability findings
        for vuln in analysis.get("vulnerabilities", []):
            findings.append({
                "finding_id": f"VULN-{len(findings) + 1:03d}",
                "category": "vulnerability",
                "severity": vuln.get("risk_level", "medium"),
                "title": vuln.get("type", "Unknown Vulnerability"),
                "description": vuln.get("description", ""),
                "impact": self._get_vulnerability_impact(vuln.get("type", "")),
                "recommendation": vuln.get("mitigation", "")
            })
        
        # Add oracle findings
        oracle_analysis = analysis.get("oracle_analysis", {})
        for vuln in oracle_analysis.get("vulnerabilities", []):
            findings.append({
                "finding_id": f"ORACLE-{len(findings) + 1:03d}",
                "category": "oracle_security",
                "severity": vuln.get("risk_level", "medium"),
                "title": f"Oracle {vuln.get('type', 'Issue')}",
                "description": vuln.get("description", ""),
                "impact": "Price manipulation and economic attacks",
                "recommendation": vuln.get("mitigation", "")
            })
        
        return findings
    
    def _generate_audit_recommendations(self, analysis: Dict) -> List[Dict[str, Any]]:
        """Generate audit recommendations"""
        recommendations = []
        
        for i, rec in enumerate(analysis.get("recommendations", []), 1):
            recommendations.append({
                "recommendation_id": f"REC-{i:03d}",
                "priority": "high" if i <= 3 else "medium",
                "description": rec,
                "implementation_effort": "medium",
                "business_impact": "high"
            })
        
        return recommendations
    
    def _generate_risk_matrix(self, analysis: Dict) -> Dict[str, Any]:
        """Generate risk assessment matrix"""
        risk_assessment = analysis.get("risk_assessment", {})
        
        return {
            "smart_contract_risk": risk_assessment.get("smart_contract_risk", {}).get("score", 0),
            "liquidity_risk": risk_assessment.get("liquidity_risk", {}).get("score", 0),
            "oracle_risk": risk_assessment.get("oracle_risk", {}).get("score", 0),
            "governance_risk": risk_assessment.get("governance_risk", {}).get("score", 0),
            "economic_risk": risk_assessment.get("economic_risk", {}).get("score", 0),
            "mev_risk": analysis.get("mev_analysis", {}).get("mev_risk_score", 0)
        }
    
    def _assess_compliance(self, analysis: Dict) -> Dict[str, Any]:
        """Assess regulatory compliance"""
        return {
            "aml_compliance": "partial",
            "kyc_requirements": "not_implemented",
            "data_protection": "gdpr_compliant",
            "securities_law": "requires_review",
            "tax_reporting": "manual_required"
        }
    
    def _generate_audit_conclusion(self, analysis: Dict) -> str:
        """Generate audit conclusion"""
        overall_risk = analysis.get("overall_risk_score", 0)
        
        if overall_risk > 70:
            return "The protocol exhibits significant security risks that require immediate attention before deployment."
        elif overall_risk > 50:
            return "The protocol has moderate security risks that should be addressed to improve overall security posture."
        elif overall_risk > 30:
            return "The protocol demonstrates good security practices with minor issues that can be addressed in future updates."
        else:
            return "The protocol exhibits strong security practices and is suitable for deployment with minimal risk."
    
    def _get_vulnerability_impact(self, vuln_type: str) -> str:
        """Get impact description for vulnerability type"""
        impacts = {
            "price_manipulation": "Attackers can manipulate prices leading to financial losses",
            "reentrancy": "Potential for fund drainage through recursive calls",
            "unauthorized_transfer": "Unauthorized access to user funds",
            "oracle_manipulation": "Price feed manipulation leading to incorrect valuations",
            "governance_attack": "Malicious control over protocol governance",
            "flash_loan_attack": "Exploitation of protocol logic through flash loans"
        }
        return impacts.get(vuln_type, "Potential security vulnerability requiring attention")

