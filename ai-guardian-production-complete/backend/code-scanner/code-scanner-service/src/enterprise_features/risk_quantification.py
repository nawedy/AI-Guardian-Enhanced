"""
Risk Quantification for AI Guardian
Financial impact assessment of vulnerabilities and security risks
"""

import json
import sqlite3
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import os
import hashlib
from collections import defaultdict

class RiskCategory(Enum):
    """Risk categories for classification"""
    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    REGULATORY = "regulatory"
    STRATEGIC = "strategic"

class ImpactLevel(Enum):
    """Impact levels for risk assessment"""
    NEGLIGIBLE = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    CATASTROPHIC = 5

class Likelihood(Enum):
    """Likelihood levels for risk assessment"""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5

@dataclass
class RiskFactor:
    """Individual risk factor"""
    factor_id: str
    name: str
    category: RiskCategory
    description: str
    base_cost: float
    probability_multiplier: float
    impact_multiplier: float
    industry_specific: bool

@dataclass
class VulnerabilityRisk:
    """Risk assessment for a specific vulnerability"""
    vulnerability_id: str
    vulnerability_type: str
    severity: str
    likelihood: Likelihood
    impact_level: ImpactLevel
    financial_impact: float
    operational_impact: float
    reputational_impact: float
    regulatory_impact: float
    risk_score: float
    mitigation_cost: float
    residual_risk: float
    time_to_exploit: int  # days
    affected_assets: List[str]

@dataclass
class BusinessImpactScenario:
    """Business impact scenario for risk modeling"""
    scenario_id: str
    name: str
    description: str
    probability: float
    direct_costs: Dict[str, float]
    indirect_costs: Dict[str, float]
    recovery_time: int  # hours
    affected_systems: List[str]
    regulatory_fines: float
    reputation_impact: float

@dataclass
class RiskAssessment:
    """Comprehensive risk assessment"""
    assessment_id: str
    assessed_at: datetime
    total_risk_exposure: float
    annual_loss_expectancy: float
    vulnerability_risks: List[VulnerabilityRisk]
    business_scenarios: List[BusinessImpactScenario]
    risk_by_category: Dict[str, float]
    recommendations: List[str]
    roi_analysis: Dict[str, Any]

class RiskQuantificationEngine:
    """Risk quantification and financial impact assessment engine"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
        self.risk_factors = self._initialize_risk_factors()
        self.industry_benchmarks = self._load_industry_benchmarks()
        self.cost_models = self._initialize_cost_models()
        
        # Business context (would be configurable)
        self.business_context = {
            'annual_revenue': 10000000,  # $10M
            'employee_count': 100,
            'industry': 'technology',
            'geographic_regions': ['north_america', 'europe'],
            'compliance_requirements': ['gdpr', 'hipaa', 'pci_dss'],
            'business_criticality': {
                'high': ['customer_data', 'payment_systems', 'core_applications'],
                'medium': ['internal_tools', 'reporting_systems'],
                'low': ['development_tools', 'test_environments']
            }
        }
    
    def _initialize_risk_factors(self) -> Dict[str, RiskFactor]:
        """Initialize risk factors for different types of vulnerabilities"""
        factors = {
            'data_breach': RiskFactor(
                factor_id='rf_001',
                name='Data Breach',
                category=RiskCategory.FINANCIAL,
                description='Cost of data breach including notification, investigation, and remediation',
                base_cost=150.0,  # per record
                probability_multiplier=1.0,
                impact_multiplier=1.5,
                industry_specific=True
            ),
            'system_downtime': RiskFactor(
                factor_id='rf_002',
                name='System Downtime',
                category=RiskCategory.OPERATIONAL,
                description='Cost of system unavailability and lost productivity',
                base_cost=5000.0,  # per hour
                probability_multiplier=1.2,
                impact_multiplier=1.0,
                industry_specific=False
            ),
            'regulatory_fine': RiskFactor(
                factor_id='rf_003',
                name='Regulatory Fine',
                category=RiskCategory.REGULATORY,
                description='Potential regulatory fines and penalties',
                base_cost=50000.0,  # base fine
                probability_multiplier=0.8,
                impact_multiplier=2.0,
                industry_specific=True
            ),
            'reputation_damage': RiskFactor(
                factor_id='rf_004',
                name='Reputation Damage',
                category=RiskCategory.REPUTATIONAL,
                description='Loss of customer trust and business',
                base_cost=100000.0,  # estimated impact
                probability_multiplier=0.6,
                impact_multiplier=1.8,
                industry_specific=True
            ),
            'intellectual_property_theft': RiskFactor(
                factor_id='rf_005',
                name='IP Theft',
                category=RiskCategory.STRATEGIC,
                description='Loss of intellectual property and competitive advantage',
                base_cost=500000.0,  # estimated value
                probability_multiplier=0.4,
                impact_multiplier=2.5,
                industry_specific=True
            ),
            'incident_response': RiskFactor(
                factor_id='rf_006',
                name='Incident Response',
                category=RiskCategory.OPERATIONAL,
                description='Cost of incident response and forensic investigation',
                base_cost=25000.0,  # per incident
                probability_multiplier=1.0,
                impact_multiplier=1.0,
                industry_specific=False
            ),
            'legal_costs': RiskFactor(
                factor_id='rf_007',
                name='Legal Costs',
                category=RiskCategory.FINANCIAL,
                description='Legal fees and litigation costs',
                base_cost=75000.0,  # estimated cost
                probability_multiplier=0.7,
                impact_multiplier=1.3,
                industry_specific=False
            ),
            'business_disruption': RiskFactor(
                factor_id='rf_008',
                name='Business Disruption',
                category=RiskCategory.OPERATIONAL,
                description='Broader business disruption beyond direct system impact',
                base_cost=10000.0,  # per day
                probability_multiplier=0.9,
                impact_multiplier=1.4,
                industry_specific=True
            )
        }
        
        return factors
    
    def _load_industry_benchmarks(self) -> Dict[str, Dict]:
        """Load industry-specific risk benchmarks"""
        return {
            'technology': {
                'data_breach_cost_per_record': 180.0,
                'average_downtime_cost_per_hour': 8000.0,
                'reputation_recovery_months': 12,
                'regulatory_fine_multiplier': 1.2,
                'cyber_insurance_coverage': 0.7
            },
            'healthcare': {
                'data_breach_cost_per_record': 250.0,
                'average_downtime_cost_per_hour': 12000.0,
                'reputation_recovery_months': 18,
                'regulatory_fine_multiplier': 2.0,
                'cyber_insurance_coverage': 0.8
            },
            'financial': {
                'data_breach_cost_per_record': 300.0,
                'average_downtime_cost_per_hour': 15000.0,
                'reputation_recovery_months': 24,
                'regulatory_fine_multiplier': 2.5,
                'cyber_insurance_coverage': 0.9
            },
            'retail': {
                'data_breach_cost_per_record': 120.0,
                'average_downtime_cost_per_hour': 6000.0,
                'reputation_recovery_months': 9,
                'regulatory_fine_multiplier': 1.0,
                'cyber_insurance_coverage': 0.6
            }
        }
    
    def _initialize_cost_models(self) -> Dict[str, Any]:
        """Initialize cost calculation models"""
        return {
            'vulnerability_severity_multipliers': {
                'critical': 3.0,
                'high': 2.0,
                'medium': 1.0,
                'low': 0.3
            },
            'exploit_likelihood_factors': {
                'sql_injection': 0.8,
                'xss': 0.6,
                'authentication_bypass': 0.9,
                'privilege_escalation': 0.7,
                'code_injection': 0.8,
                'path_traversal': 0.5,
                'information_disclosure': 0.4,
                'csrf': 0.3
            },
            'asset_criticality_multipliers': {
                'high': 2.5,
                'medium': 1.5,
                'low': 0.8
            },
            'time_decay_factors': {
                'immediate': 1.0,
                'days_1_7': 0.9,
                'days_8_30': 0.7,
                'days_31_90': 0.5,
                'days_90_plus': 0.3
            }
        }
    
    def assess_vulnerability_risk(self, vulnerability: Dict[str, Any]) -> VulnerabilityRisk:
        """Assess financial risk for a specific vulnerability"""
        try:
            vuln_type = vulnerability.get('type', 'unknown')
            severity = vulnerability.get('severity', 'medium')
            affected_assets = vulnerability.get('affected_assets', [])
            
            # Calculate likelihood
            likelihood = self._calculate_likelihood(vuln_type, severity, vulnerability)
            
            # Calculate impact level
            impact_level = self._calculate_impact_level(vuln_type, affected_assets, vulnerability)
            
            # Calculate financial impacts
            financial_impact = self._calculate_financial_impact(vuln_type, severity, affected_assets)
            operational_impact = self._calculate_operational_impact(vuln_type, severity, affected_assets)
            reputational_impact = self._calculate_reputational_impact(vuln_type, severity, affected_assets)
            regulatory_impact = self._calculate_regulatory_impact(vuln_type, severity, affected_assets)
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(likelihood, impact_level, financial_impact)
            
            # Calculate mitigation cost
            mitigation_cost = self._calculate_mitigation_cost(vuln_type, severity)
            
            # Calculate residual risk after mitigation
            residual_risk = risk_score * 0.1  # Assume 90% risk reduction with proper mitigation
            
            # Estimate time to exploit
            time_to_exploit = self._estimate_time_to_exploit(vuln_type, severity)
            
            return VulnerabilityRisk(
                vulnerability_id=vulnerability.get('id', 'unknown'),
                vulnerability_type=vuln_type,
                severity=severity,
                likelihood=likelihood,
                impact_level=impact_level,
                financial_impact=financial_impact,
                operational_impact=operational_impact,
                reputational_impact=reputational_impact,
                regulatory_impact=regulatory_impact,
                risk_score=risk_score,
                mitigation_cost=mitigation_cost,
                residual_risk=residual_risk,
                time_to_exploit=time_to_exploit,
                affected_assets=affected_assets
            )
            
        except Exception as e:
            print(f"Error assessing vulnerability risk: {e}")
            return self._create_default_risk_assessment(vulnerability)
    
    def _calculate_likelihood(self, vuln_type: str, severity: str, vulnerability: Dict) -> Likelihood:
        """Calculate likelihood of exploitation"""
        base_likelihood = self.cost_models['exploit_likelihood_factors'].get(vuln_type, 0.5)
        
        # Adjust based on severity
        severity_adjustment = {
            'critical': 0.3,
            'high': 0.2,
            'medium': 0.0,
            'low': -0.2
        }
        
        adjusted_likelihood = base_likelihood + severity_adjustment.get(severity, 0.0)
        
        # Adjust based on exposure (public-facing vs internal)
        if vulnerability.get('public_facing', False):
            adjusted_likelihood += 0.2
        
        # Adjust based on known exploits
        if vulnerability.get('known_exploits', False):
            adjusted_likelihood += 0.3
        
        # Convert to enum
        if adjusted_likelihood >= 0.8:
            return Likelihood.VERY_HIGH
        elif adjusted_likelihood >= 0.6:
            return Likelihood.HIGH
        elif adjusted_likelihood >= 0.4:
            return Likelihood.MEDIUM
        elif adjusted_likelihood >= 0.2:
            return Likelihood.LOW
        else:
            return Likelihood.VERY_LOW
    
    def _calculate_impact_level(self, vuln_type: str, affected_assets: List[str], vulnerability: Dict) -> ImpactLevel:
        """Calculate impact level based on vulnerability and affected assets"""
        base_impact = 2  # Medium by default
        
        # Adjust based on vulnerability type
        high_impact_types = ['sql_injection', 'authentication_bypass', 'privilege_escalation', 'code_injection']
        if vuln_type in high_impact_types:
            base_impact += 1
        
        # Adjust based on affected assets
        for asset in affected_assets:
            if asset in self.business_context['business_criticality']['high']:
                base_impact += 2
            elif asset in self.business_context['business_criticality']['medium']:
                base_impact += 1
        
        # Adjust based on data sensitivity
        if vulnerability.get('affects_sensitive_data', False):
            base_impact += 1
        
        # Cap at maximum impact level
        impact_value = min(5, max(1, base_impact))
        
        return ImpactLevel(impact_value)
    
    def _calculate_financial_impact(self, vuln_type: str, severity: str, affected_assets: List[str]) -> float:
        """Calculate direct financial impact"""
        total_impact = 0.0
        
        # Base cost from vulnerability type
        if vuln_type in ['sql_injection', 'authentication_bypass']:
            # High potential for data breach
            records_at_risk = self._estimate_records_at_risk(affected_assets)
            breach_cost_per_record = self.industry_benchmarks[self.business_context['industry']]['data_breach_cost_per_record']
            total_impact += records_at_risk * breach_cost_per_record
        
        # System downtime costs
        if vuln_type in ['code_injection', 'privilege_escalation']:
            downtime_hours = self._estimate_downtime_hours(severity)
            downtime_cost_per_hour = self.industry_benchmarks[self.business_context['industry']]['average_downtime_cost_per_hour']
            total_impact += downtime_hours * downtime_cost_per_hour
        
        # Incident response costs
        incident_response_cost = self.risk_factors['incident_response'].base_cost
        severity_multiplier = self.cost_models['vulnerability_severity_multipliers'][severity]
        total_impact += incident_response_cost * severity_multiplier
        
        # Legal and compliance costs
        if severity in ['critical', 'high']:
            total_impact += self.risk_factors['legal_costs'].base_cost * 0.5
        
        return total_impact
    
    def _calculate_operational_impact(self, vuln_type: str, severity: str, affected_assets: List[str]) -> float:
        """Calculate operational impact"""
        operational_cost = 0.0
        
        # Productivity loss
        if affected_assets:
            affected_users = len(affected_assets) * 10  # Estimate 10 users per asset
            productivity_loss_per_user_per_day = 200.0  # $200 per user per day
            disruption_days = self._estimate_disruption_days(severity)
            operational_cost += affected_users * productivity_loss_per_user_per_day * disruption_days
        
        # Business process disruption
        if vuln_type in ['authentication_bypass', 'privilege_escalation']:
            business_disruption_cost = self.risk_factors['business_disruption'].base_cost
            severity_multiplier = self.cost_models['vulnerability_severity_multipliers'][severity]
            operational_cost += business_disruption_cost * severity_multiplier
        
        return operational_cost
    
    def _calculate_reputational_impact(self, vuln_type: str, severity: str, affected_assets: List[str]) -> float:
        """Calculate reputational impact"""
        if severity not in ['critical', 'high']:
            return 0.0
        
        # Base reputation damage
        reputation_cost = self.risk_factors['reputation_damage'].base_cost
        
        # Adjust based on customer-facing systems
        customer_facing_assets = [asset for asset in affected_assets 
                                if 'customer' in asset.lower() or 'public' in asset.lower()]
        if customer_facing_assets:
            reputation_cost *= 1.5
        
        # Adjust based on data sensitivity
        if vuln_type in ['sql_injection', 'authentication_bypass']:
            reputation_cost *= 1.3
        
        return reputation_cost
    
    def _calculate_regulatory_impact(self, vuln_type: str, severity: str, affected_assets: List[str]) -> float:
        """Calculate regulatory impact and potential fines"""
        regulatory_cost = 0.0
        
        # Check if vulnerability affects regulated data
        affects_regulated_data = any('customer_data' in asset.lower() or 'payment' in asset.lower() 
                                   for asset in affected_assets)
        
        if affects_regulated_data and severity in ['critical', 'high']:
            base_fine = self.risk_factors['regulatory_fine'].base_cost
            industry_multiplier = self.industry_benchmarks[self.business_context['industry']]['regulatory_fine_multiplier']
            
            # GDPR fines (up to 4% of annual revenue)
            if 'gdpr' in self.business_context['compliance_requirements']:
                max_gdpr_fine = self.business_context['annual_revenue'] * 0.04
                regulatory_cost += min(base_fine * industry_multiplier, max_gdpr_fine * 0.1)
            
            # Other compliance fines
            for compliance in self.business_context['compliance_requirements']:
                if compliance != 'gdpr':
                    regulatory_cost += base_fine * 0.5
        
        return regulatory_cost
    
    def _calculate_risk_score(self, likelihood: Likelihood, impact: ImpactLevel, financial_impact: float) -> float:
        """Calculate overall risk score"""
        # Base risk score (1-25 scale)
        base_score = likelihood.value * impact.value
        
        # Normalize financial impact to 0-1 scale
        max_expected_impact = 1000000.0  # $1M
        financial_factor = min(1.0, financial_impact / max_expected_impact)
        
        # Combine base score with financial factor
        risk_score = base_score * (1 + financial_factor)
        
        return min(25.0, risk_score)
    
    def _calculate_mitigation_cost(self, vuln_type: str, severity: str) -> float:
        """Calculate cost to mitigate the vulnerability"""
        base_costs = {
            'sql_injection': 5000.0,
            'xss': 3000.0,
            'authentication_bypass': 8000.0,
            'privilege_escalation': 10000.0,
            'code_injection': 7000.0,
            'path_traversal': 2000.0,
            'information_disclosure': 1500.0,
            'csrf': 1000.0
        }
        
        base_cost = base_costs.get(vuln_type, 3000.0)
        severity_multiplier = self.cost_models['vulnerability_severity_multipliers'][severity]
        
        return base_cost * severity_multiplier
    
    def _estimate_time_to_exploit(self, vuln_type: str, severity: str) -> int:
        """Estimate time to exploit in days"""
        base_times = {
            'sql_injection': 1,
            'xss': 3,
            'authentication_bypass': 1,
            'privilege_escalation': 2,
            'code_injection': 1,
            'path_traversal': 5,
            'information_disclosure': 7,
            'csrf': 10
        }
        
        base_time = base_times.get(vuln_type, 7)
        
        # Adjust based on severity
        if severity == 'critical':
            return max(1, base_time // 2)
        elif severity == 'high':
            return base_time
        elif severity == 'medium':
            return base_time * 2
        else:
            return base_time * 4
    
    def _estimate_records_at_risk(self, affected_assets: List[str]) -> int:
        """Estimate number of records at risk"""
        base_records = 1000  # Default estimate
        
        for asset in affected_assets:
            if 'customer' in asset.lower():
                base_records += 10000
            elif 'user' in asset.lower():
                base_records += 5000
            elif 'payment' in asset.lower():
                base_records += 15000
            elif 'database' in asset.lower():
                base_records += 20000
        
        return base_records
    
    def _estimate_downtime_hours(self, severity: str) -> int:
        """Estimate system downtime in hours"""
        downtime_estimates = {
            'critical': 24,
            'high': 8,
            'medium': 4,
            'low': 1
        }
        
        return downtime_estimates.get(severity, 4)
    
    def _estimate_disruption_days(self, severity: str) -> int:
        """Estimate business disruption in days"""
        disruption_estimates = {
            'critical': 5,
            'high': 3,
            'medium': 1,
            'low': 0
        }
        
        return disruption_estimates.get(severity, 1)
    
    def _create_default_risk_assessment(self, vulnerability: Dict) -> VulnerabilityRisk:
        """Create default risk assessment for error cases"""
        return VulnerabilityRisk(
            vulnerability_id=vulnerability.get('id', 'unknown'),
            vulnerability_type=vulnerability.get('type', 'unknown'),
            severity=vulnerability.get('severity', 'medium'),
            likelihood=Likelihood.MEDIUM,
            impact_level=ImpactLevel.MODERATE,
            financial_impact=10000.0,
            operational_impact=5000.0,
            reputational_impact=0.0,
            regulatory_impact=0.0,
            risk_score=9.0,
            mitigation_cost=3000.0,
            residual_risk=0.9,
            time_to_exploit=7,
            affected_assets=vulnerability.get('affected_assets', [])
        )
    
    def generate_business_impact_scenarios(self, vulnerabilities: List[Dict]) -> List[BusinessImpactScenario]:
        """Generate business impact scenarios based on vulnerabilities"""
        scenarios = []
        
        try:
            # Scenario 1: Major Data Breach
            data_breach_vulns = [v for v in vulnerabilities 
                               if v.get('type') in ['sql_injection', 'authentication_bypass'] 
                               and v.get('severity') in ['critical', 'high']]
            
            if data_breach_vulns:
                scenario = BusinessImpactScenario(
                    scenario_id='scenario_001',
                    name='Major Data Breach',
                    description='Large-scale data breach affecting customer and payment data',
                    probability=0.15,
                    direct_costs={
                        'notification_costs': 50000.0,
                        'investigation_costs': 100000.0,
                        'legal_costs': 200000.0,
                        'regulatory_fines': 500000.0
                    },
                    indirect_costs={
                        'reputation_damage': 1000000.0,
                        'customer_churn': 500000.0,
                        'business_disruption': 300000.0
                    },
                    recovery_time=720,  # 30 days
                    affected_systems=['customer_database', 'payment_system', 'web_application'],
                    regulatory_fines=500000.0,
                    reputation_impact=1000000.0
                )
                scenarios.append(scenario)
            
            # Scenario 2: System Compromise
            system_vulns = [v for v in vulnerabilities 
                          if v.get('type') in ['privilege_escalation', 'code_injection']]
            
            if system_vulns:
                scenario = BusinessImpactScenario(
                    scenario_id='scenario_002',
                    name='System Compromise',
                    description='Complete system compromise leading to service disruption',
                    probability=0.10,
                    direct_costs={
                        'incident_response': 75000.0,
                        'system_rebuild': 150000.0,
                        'data_recovery': 50000.0
                    },
                    indirect_costs={
                        'downtime_costs': 200000.0,
                        'productivity_loss': 100000.0,
                        'customer_compensation': 75000.0
                    },
                    recovery_time=168,  # 7 days
                    affected_systems=['core_application', 'database_server', 'authentication_system'],
                    regulatory_fines=0.0,
                    reputation_impact=250000.0
                )
                scenarios.append(scenario)
            
            # Scenario 3: Intellectual Property Theft
            ip_vulns = [v for v in vulnerabilities 
                       if v.get('affects_sensitive_data', False)]
            
            if ip_vulns:
                scenario = BusinessImpactScenario(
                    scenario_id='scenario_003',
                    name='Intellectual Property Theft',
                    description='Theft of proprietary code and business intelligence',
                    probability=0.08,
                    direct_costs={
                        'forensic_investigation': 100000.0,
                        'legal_action': 300000.0,
                        'security_enhancement': 200000.0
                    },
                    indirect_costs={
                        'competitive_disadvantage': 2000000.0,
                        'lost_revenue': 1000000.0,
                        'market_share_loss': 500000.0
                    },
                    recovery_time=8760,  # 1 year
                    affected_systems=['source_code_repository', 'development_environment', 'documentation_system'],
                    regulatory_fines=0.0,
                    reputation_impact=300000.0
                )
                scenarios.append(scenario)
            
            return scenarios
            
        except Exception as e:
            print(f"Error generating business impact scenarios: {e}")
            return []
    
    def calculate_annual_loss_expectancy(self, vulnerability_risks: List[VulnerabilityRisk], 
                                       scenarios: List[BusinessImpactScenario]) -> float:
        """Calculate Annual Loss Expectancy (ALE)"""
        try:
            total_ale = 0.0
            
            # Calculate ALE from individual vulnerabilities
            for risk in vulnerability_risks:
                # Convert likelihood to probability
                likelihood_probability = risk.likelihood.value / 5.0
                
                # Calculate Single Loss Expectancy (SLE)
                sle = risk.financial_impact + risk.operational_impact + risk.reputational_impact + risk.regulatory_impact
                
                # Calculate Annual Rate of Occurrence (ARO)
                # Assume vulnerabilities could be exploited multiple times per year
                aro = likelihood_probability * 2  # Up to 2 times per year for high likelihood
                
                # ALE = SLE * ARO
                vulnerability_ale = sle * aro
                total_ale += vulnerability_ale
            
            # Add scenario-based ALE
            for scenario in scenarios:
                scenario_sle = sum(scenario.direct_costs.values()) + sum(scenario.indirect_costs.values())
                scenario_ale = scenario_sle * scenario.probability
                total_ale += scenario_ale
            
            return total_ale
            
        except Exception as e:
            print(f"Error calculating ALE: {e}")
            return 0.0
    
    def perform_roi_analysis(self, vulnerability_risks: List[VulnerabilityRisk], 
                           mitigation_budget: float) -> Dict[str, Any]:
        """Perform ROI analysis for security investments"""
        try:
            # Calculate total risk exposure
            total_risk_exposure = sum(risk.financial_impact + risk.operational_impact + 
                                    risk.reputational_impact + risk.regulatory_impact 
                                    for risk in vulnerability_risks)
            
            # Calculate total mitigation cost
            total_mitigation_cost = sum(risk.mitigation_cost for risk in vulnerability_risks)
            
            # Calculate risk reduction
            total_residual_risk = sum(risk.residual_risk for risk in vulnerability_risks)
            risk_reduction = total_risk_exposure - total_residual_risk
            
            # Calculate ROI
            if total_mitigation_cost > 0:
                roi_ratio = risk_reduction / total_mitigation_cost
                roi_percentage = (roi_ratio - 1) * 100
            else:
                roi_ratio = 0
                roi_percentage = 0
            
            # Prioritize vulnerabilities by ROI
            vulnerability_priorities = []
            for risk in vulnerability_risks:
                risk_value = risk.financial_impact + risk.operational_impact + risk.reputational_impact + risk.regulatory_impact
                if risk.mitigation_cost > 0:
                    vuln_roi = (risk_value - risk.residual_risk) / risk.mitigation_cost
                else:
                    vuln_roi = 0
                
                vulnerability_priorities.append({
                    'vulnerability_id': risk.vulnerability_id,
                    'vulnerability_type': risk.vulnerability_type,
                    'risk_value': risk_value,
                    'mitigation_cost': risk.mitigation_cost,
                    'roi': vuln_roi,
                    'priority': 'high' if vuln_roi > 3 else 'medium' if vuln_roi > 1 else 'low'
                })
            
            # Sort by ROI
            vulnerability_priorities.sort(key=lambda x: x['roi'], reverse=True)
            
            # Budget allocation recommendations
            budget_allocation = self._optimize_budget_allocation(vulnerability_priorities, mitigation_budget)
            
            return {
                'total_risk_exposure': total_risk_exposure,
                'total_mitigation_cost': total_mitigation_cost,
                'risk_reduction': risk_reduction,
                'roi_ratio': roi_ratio,
                'roi_percentage': roi_percentage,
                'vulnerability_priorities': vulnerability_priorities,
                'budget_allocation': budget_allocation,
                'payback_period_months': max(1, total_mitigation_cost / (risk_reduction / 12)) if risk_reduction > 0 else float('inf')
            }
            
        except Exception as e:
            print(f"Error performing ROI analysis: {e}")
            return {}
    
    def _optimize_budget_allocation(self, priorities: List[Dict], budget: float) -> Dict[str, Any]:
        """Optimize budget allocation across vulnerabilities"""
        allocated_budget = 0.0
        recommended_fixes = []
        deferred_fixes = []
        
        for vuln in priorities:
            if allocated_budget + vuln['mitigation_cost'] <= budget:
                recommended_fixes.append(vuln)
                allocated_budget += vuln['mitigation_cost']
            else:
                deferred_fixes.append(vuln)
        
        return {
            'budget_available': budget,
            'budget_allocated': allocated_budget,
            'budget_remaining': budget - allocated_budget,
            'recommended_fixes': recommended_fixes,
            'deferred_fixes': deferred_fixes,
            'coverage_percentage': (allocated_budget / sum(v['mitigation_cost'] for v in priorities)) * 100 if priorities else 0
        }
    
    def generate_comprehensive_risk_assessment(self, vulnerabilities: List[Dict] = None) -> RiskAssessment:
        """Generate comprehensive risk assessment"""
        try:
            # Get vulnerabilities from database if not provided
            if vulnerabilities is None:
                vulnerabilities = self._get_vulnerabilities_from_database()
            
            # Assess individual vulnerability risks
            vulnerability_risks = []
            for vuln in vulnerabilities:
                risk = self.assess_vulnerability_risk(vuln)
                vulnerability_risks.append(risk)
            
            # Generate business impact scenarios
            scenarios = self.generate_business_impact_scenarios(vulnerabilities)
            
            # Calculate total risk exposure
            total_risk_exposure = sum(risk.financial_impact + risk.operational_impact + 
                                    risk.reputational_impact + risk.regulatory_impact 
                                    for risk in vulnerability_risks)
            
            # Calculate Annual Loss Expectancy
            ale = self.calculate_annual_loss_expectancy(vulnerability_risks, scenarios)
            
            # Calculate risk by category
            risk_by_category = {
                'financial': sum(risk.financial_impact for risk in vulnerability_risks),
                'operational': sum(risk.operational_impact for risk in vulnerability_risks),
                'reputational': sum(risk.reputational_impact for risk in vulnerability_risks),
                'regulatory': sum(risk.regulatory_impact for risk in vulnerability_risks)
            }
            
            # Generate recommendations
            recommendations = self._generate_risk_recommendations(vulnerability_risks, scenarios)
            
            # Perform ROI analysis
            roi_analysis = self.perform_roi_analysis(vulnerability_risks, 500000.0)  # $500K budget
            
            # Create assessment
            assessment = RiskAssessment(
                assessment_id=hashlib.md5(f"risk_assessment_{datetime.now()}".encode()).hexdigest()[:16],
                assessed_at=datetime.now(),
                total_risk_exposure=total_risk_exposure,
                annual_loss_expectancy=ale,
                vulnerability_risks=vulnerability_risks,
                business_scenarios=scenarios,
                risk_by_category=risk_by_category,
                recommendations=recommendations,
                roi_analysis=roi_analysis
            )
            
            return assessment
            
        except Exception as e:
            print(f"Error generating risk assessment: {e}")
            return self._create_default_risk_assessment_result()
    
    def _get_vulnerabilities_from_database(self) -> List[Dict]:
        """Get vulnerabilities from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, type, severity, file_path, line_number, description
                FROM scan_results 
                WHERE created_at >= date('now', '-30 days')
                ORDER BY severity DESC, created_at DESC
                LIMIT 100
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            vulnerabilities = []
            for row in results:
                vuln = {
                    'id': row[0],
                    'type': row[1],
                    'severity': row[2],
                    'file_path': row[3],
                    'line_number': row[4],
                    'description': row[5],
                    'affected_assets': [row[3]],  # Use file path as asset
                    'public_facing': 'web' in row[3].lower() or 'api' in row[3].lower(),
                    'affects_sensitive_data': 'user' in row[5].lower() or 'password' in row[5].lower() or 'payment' in row[5].lower()
                }
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error getting vulnerabilities from database: {e}")
            return []
    
    def _generate_risk_recommendations(self, vulnerability_risks: List[VulnerabilityRisk], 
                                     scenarios: List[BusinessImpactScenario]) -> List[str]:
        """Generate risk management recommendations"""
        recommendations = []
        
        # High-risk vulnerabilities
        high_risk_vulns = [risk for risk in vulnerability_risks if risk.risk_score >= 15]
        if high_risk_vulns:
            recommendations.append(f"Immediately address {len(high_risk_vulns)} high-risk vulnerabilities")
        
        # Financial impact recommendations
        total_financial_impact = sum(risk.financial_impact for risk in vulnerability_risks)
        if total_financial_impact > 1000000:
            recommendations.append("Consider cyber insurance to mitigate financial exposure")
        
        # Operational recommendations
        total_operational_impact = sum(risk.operational_impact for risk in vulnerability_risks)
        if total_operational_impact > 500000:
            recommendations.append("Implement business continuity and disaster recovery plans")
        
        # Regulatory recommendations
        total_regulatory_impact = sum(risk.regulatory_impact for risk in vulnerability_risks)
        if total_regulatory_impact > 100000:
            recommendations.append("Enhance compliance monitoring and reporting")
        
        # Scenario-based recommendations
        if scenarios:
            recommendations.append("Develop incident response plans for identified threat scenarios")
        
        # General recommendations
        recommendations.extend([
            "Implement continuous security monitoring",
            "Regular security awareness training for employees",
            "Establish security metrics and KPIs",
            "Regular third-party security assessments"
        ])
        
        return recommendations[:8]  # Limit to top 8
    
    def _create_default_risk_assessment_result(self) -> RiskAssessment:
        """Create default risk assessment for error cases"""
        return RiskAssessment(
            assessment_id="error",
            assessed_at=datetime.now(),
            total_risk_exposure=0.0,
            annual_loss_expectancy=0.0,
            vulnerability_risks=[],
            business_scenarios=[],
            risk_by_category={},
            recommendations=["Fix risk assessment system errors"],
            roi_analysis={}
        )
    
    def export_risk_report(self, assessment: RiskAssessment, format: str = 'json') -> Dict[str, Any]:
        """Export risk assessment report in specified format"""
        try:
            if format.lower() == 'json':
                # Convert to JSON-serializable format
                report = {
                    'assessment_id': assessment.assessment_id,
                    'assessed_at': assessment.assessed_at.isoformat(),
                    'executive_summary': {
                        'total_risk_exposure': assessment.total_risk_exposure,
                        'annual_loss_expectancy': assessment.annual_loss_expectancy,
                        'vulnerability_count': len(assessment.vulnerability_risks),
                        'scenario_count': len(assessment.business_scenarios)
                    },
                    'risk_breakdown': assessment.risk_by_category,
                    'vulnerability_risks': [
                        {
                            'vulnerability_id': risk.vulnerability_id,
                            'vulnerability_type': risk.vulnerability_type,
                            'severity': risk.severity,
                            'likelihood': risk.likelihood.name,
                            'impact_level': risk.impact_level.name,
                            'financial_impact': risk.financial_impact,
                            'operational_impact': risk.operational_impact,
                            'reputational_impact': risk.reputational_impact,
                            'regulatory_impact': risk.regulatory_impact,
                            'risk_score': risk.risk_score,
                            'mitigation_cost': risk.mitigation_cost,
                            'time_to_exploit': risk.time_to_exploit
                        } for risk in assessment.vulnerability_risks
                    ],
                    'business_scenarios': [
                        {
                            'scenario_id': scenario.scenario_id,
                            'name': scenario.name,
                            'description': scenario.description,
                            'probability': scenario.probability,
                            'total_direct_costs': sum(scenario.direct_costs.values()),
                            'total_indirect_costs': sum(scenario.indirect_costs.values()),
                            'recovery_time_hours': scenario.recovery_time
                        } for scenario in assessment.business_scenarios
                    ],
                    'recommendations': assessment.recommendations,
                    'roi_analysis': assessment.roi_analysis
                }
                
                return report
            
            else:
                return {'error': f'Unsupported format: {format}'}
                
        except Exception as e:
            return {'error': f'Error exporting risk report: {str(e)}'}

