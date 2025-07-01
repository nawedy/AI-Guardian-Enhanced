"""
Compliance Automation for AI Guardian
Automated compliance report generation and monitoring
"""

import json
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import os
import hashlib
from collections import defaultdict, Counter

class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    UNKNOWN = "unknown"

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    CCPA = "ccpa"
    ISO27001 = "iso27001"
    NIST = "nist"

@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    requirement_id: str
    framework: ComplianceFramework
    category: str
    title: str
    description: str
    mandatory: bool
    evidence_required: List[str]
    automated_check: bool
    check_frequency: str
    penalty_risk: str

@dataclass
class ComplianceEvidence:
    """Evidence for compliance requirement"""
    evidence_id: str
    requirement_id: str
    evidence_type: str
    description: str
    collected_at: datetime
    valid_until: Optional[datetime]
    automated: bool
    file_path: Optional[str]
    metadata: Dict[str, Any]

@dataclass
class ComplianceAssessment:
    """Compliance assessment result"""
    assessment_id: str
    framework: ComplianceFramework
    assessed_at: datetime
    overall_status: ComplianceStatus
    compliance_score: float
    requirements_total: int
    requirements_compliant: int
    requirements_non_compliant: int
    requirements_partial: int
    critical_gaps: List[str]
    recommendations: List[str]
    next_assessment_due: datetime

class ComplianceAutomation:
    """Automated compliance monitoring and reporting system"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
        self.requirements = self._load_compliance_requirements()
        self.evidence_collectors = self._initialize_evidence_collectors()
        self.report_templates = self._load_report_templates()
        
        # Initialize database tables
        self._initialize_compliance_tables()
    
    def _load_compliance_requirements(self) -> Dict[ComplianceFramework, List[ComplianceRequirement]]:
        """Load compliance requirements for different frameworks"""
        requirements = {
            ComplianceFramework.GDPR: [
                ComplianceRequirement(
                    requirement_id="gdpr_001",
                    framework=ComplianceFramework.GDPR,
                    category="Data Protection",
                    title="Data Encryption at Rest",
                    description="Personal data must be encrypted when stored",
                    mandatory=True,
                    evidence_required=["encryption_config", "security_scan_results"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="high"
                ),
                ComplianceRequirement(
                    requirement_id="gdpr_002",
                    framework=ComplianceFramework.GDPR,
                    category="Data Protection",
                    title="Data Encryption in Transit",
                    description="Personal data must be encrypted during transmission",
                    mandatory=True,
                    evidence_required=["tls_config", "network_scan_results"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="high"
                ),
                ComplianceRequirement(
                    requirement_id="gdpr_003",
                    framework=ComplianceFramework.GDPR,
                    category="Access Control",
                    title="Access Logging",
                    description="All access to personal data must be logged",
                    mandatory=True,
                    evidence_required=["access_logs", "audit_trail"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="medium"
                ),
                ComplianceRequirement(
                    requirement_id="gdpr_004",
                    framework=ComplianceFramework.GDPR,
                    category="Data Subject Rights",
                    title="Data Portability",
                    description="Ability to export user data in machine-readable format",
                    mandatory=True,
                    evidence_required=["export_functionality", "test_results"],
                    automated_check=False,
                    check_frequency="monthly",
                    penalty_risk="medium"
                )
            ],
            ComplianceFramework.HIPAA: [
                ComplianceRequirement(
                    requirement_id="hipaa_001",
                    framework=ComplianceFramework.HIPAA,
                    category="Administrative Safeguards",
                    title="Access Management",
                    description="Unique user identification and access controls for PHI",
                    mandatory=True,
                    evidence_required=["user_access_matrix", "authentication_logs"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="high"
                ),
                ComplianceRequirement(
                    requirement_id="hipaa_002",
                    framework=ComplianceFramework.HIPAA,
                    category="Physical Safeguards",
                    title="Workstation Security",
                    description="Workstations accessing PHI must be secured",
                    mandatory=True,
                    evidence_required=["device_compliance", "security_config"],
                    automated_check=True,
                    check_frequency="weekly",
                    penalty_risk="medium"
                ),
                ComplianceRequirement(
                    requirement_id="hipaa_003",
                    framework=ComplianceFramework.HIPAA,
                    category="Technical Safeguards",
                    title="Audit Controls",
                    description="Audit controls to record access to PHI",
                    mandatory=True,
                    evidence_required=["audit_logs", "monitoring_reports"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="high"
                )
            ],
            ComplianceFramework.PCI_DSS: [
                ComplianceRequirement(
                    requirement_id="pci_001",
                    framework=ComplianceFramework.PCI_DSS,
                    category="Network Security",
                    title="Firewall Configuration",
                    description="Install and maintain firewall configuration",
                    mandatory=True,
                    evidence_required=["firewall_config", "network_diagram"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="high"
                ),
                ComplianceRequirement(
                    requirement_id="pci_002",
                    framework=ComplianceFramework.PCI_DSS,
                    category="Data Protection",
                    title="Cardholder Data Encryption",
                    description="Protect stored cardholder data with encryption",
                    mandatory=True,
                    evidence_required=["encryption_evidence", "key_management"],
                    automated_check=True,
                    check_frequency="daily",
                    penalty_risk="critical"
                ),
                ComplianceRequirement(
                    requirement_id="pci_003",
                    framework=ComplianceFramework.PCI_DSS,
                    category="Vulnerability Management",
                    title="Regular Security Testing",
                    description="Regularly test security systems and processes",
                    mandatory=True,
                    evidence_required=["penetration_test_reports", "vulnerability_scans"],
                    automated_check=True,
                    check_frequency="quarterly",
                    penalty_risk="high"
                )
            ]
        }
        
        return requirements
    
    def _initialize_evidence_collectors(self) -> Dict[str, Any]:
        """Initialize automated evidence collection methods"""
        return {
            'security_scan_results': {
                'method': 'query_vulnerability_database',
                'frequency': 'daily',
                'retention_days': 90
            },
            'encryption_config': {
                'method': 'check_encryption_settings',
                'frequency': 'daily',
                'retention_days': 30
            },
            'access_logs': {
                'method': 'collect_access_logs',
                'frequency': 'daily',
                'retention_days': 365
            },
            'audit_trail': {
                'method': 'generate_audit_trail',
                'frequency': 'daily',
                'retention_days': 365
            },
            'network_scan_results': {
                'method': 'perform_network_scan',
                'frequency': 'weekly',
                'retention_days': 90
            }
        }
    
    def _load_report_templates(self) -> Dict[ComplianceFramework, Dict]:
        """Load report templates for different frameworks"""
        return {
            ComplianceFramework.GDPR: {
                'title': 'GDPR Compliance Report',
                'sections': [
                    'Executive Summary',
                    'Data Protection Measures',
                    'Access Controls',
                    'Data Subject Rights',
                    'Breach Notification Procedures',
                    'Recommendations'
                ],
                'required_evidence': ['encryption_config', 'access_logs', 'data_mapping']
            },
            ComplianceFramework.HIPAA: {
                'title': 'HIPAA Compliance Report',
                'sections': [
                    'Executive Summary',
                    'Administrative Safeguards',
                    'Physical Safeguards',
                    'Technical Safeguards',
                    'Risk Assessment',
                    'Recommendations'
                ],
                'required_evidence': ['access_controls', 'audit_logs', 'risk_assessment']
            },
            ComplianceFramework.PCI_DSS: {
                'title': 'PCI DSS Compliance Report',
                'sections': [
                    'Executive Summary',
                    'Network Security Controls',
                    'Data Protection',
                    'Vulnerability Management',
                    'Access Control',
                    'Monitoring and Testing',
                    'Information Security Policy',
                    'Recommendations'
                ],
                'required_evidence': ['network_config', 'encryption_evidence', 'vulnerability_scans']
            }
        }
    
    def _initialize_compliance_tables(self):
        """Initialize database tables for compliance tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Compliance evidence table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS compliance_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    requirement_id TEXT,
                    evidence_type TEXT,
                    description TEXT,
                    collected_at TEXT,
                    valid_until TEXT,
                    automated BOOLEAN,
                    file_path TEXT,
                    metadata TEXT
                )
            """)
            
            # Compliance assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    framework TEXT,
                    assessed_at TEXT,
                    overall_status TEXT,
                    compliance_score REAL,
                    requirements_total INTEGER,
                    requirements_compliant INTEGER,
                    requirements_non_compliant INTEGER,
                    requirements_partial INTEGER,
                    critical_gaps TEXT,
                    recommendations TEXT,
                    next_assessment_due TEXT
                )
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error initializing compliance tables: {e}")
    
    def collect_evidence_automatically(self, requirement_id: str = None) -> List[ComplianceEvidence]:
        """Automatically collect evidence for compliance requirements"""
        evidence_collected = []
        
        try:
            # Get requirements that need evidence collection
            requirements_to_check = []
            
            if requirement_id:
                # Collect for specific requirement
                for framework_reqs in self.requirements.values():
                    for req in framework_reqs:
                        if req.requirement_id == requirement_id:
                            requirements_to_check.append(req)
            else:
                # Collect for all requirements with automated checks
                for framework_reqs in self.requirements.values():
                    for req in framework_reqs:
                        if req.automated_check:
                            requirements_to_check.append(req)
            
            # Collect evidence for each requirement
            for req in requirements_to_check:
                for evidence_type in req.evidence_required:
                    if evidence_type in self.evidence_collectors:
                        evidence = self._collect_specific_evidence(req, evidence_type)
                        if evidence:
                            evidence_collected.append(evidence)
                            self._store_evidence(evidence)
            
            return evidence_collected
            
        except Exception as e:
            print(f"Error collecting evidence: {e}")
            return []
    
    def _collect_specific_evidence(self, requirement: ComplianceRequirement, evidence_type: str) -> Optional[ComplianceEvidence]:
        """Collect specific type of evidence"""
        try:
            collector_config = self.evidence_collectors.get(evidence_type)
            if not collector_config:
                return None
            
            method = collector_config['method']
            evidence_data = None
            
            if method == 'query_vulnerability_database':
                evidence_data = self._query_vulnerability_database()
            elif method == 'check_encryption_settings':
                evidence_data = self._check_encryption_settings()
            elif method == 'collect_access_logs':
                evidence_data = self._collect_access_logs()
            elif method == 'generate_audit_trail':
                evidence_data = self._generate_audit_trail()
            elif method == 'perform_network_scan':
                evidence_data = self._perform_network_scan()
            
            if evidence_data:
                evidence = ComplianceEvidence(
                    evidence_id=hashlib.md5(f"{requirement.requirement_id}{evidence_type}{datetime.now()}".encode()).hexdigest()[:16],
                    requirement_id=requirement.requirement_id,
                    evidence_type=evidence_type,
                    description=f"Automated collection of {evidence_type} for {requirement.title}",
                    collected_at=datetime.now(),
                    valid_until=datetime.now() + timedelta(days=collector_config['retention_days']),
                    automated=True,
                    file_path=None,
                    metadata=evidence_data
                )
                return evidence
            
            return None
            
        except Exception as e:
            print(f"Error collecting {evidence_type}: {e}")
            return None
    
    def _query_vulnerability_database(self) -> Dict[str, Any]:
        """Query vulnerability database for compliance evidence"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent vulnerability scan results
            cursor.execute("""
                SELECT type, severity, COUNT(*) as count
                FROM scan_results 
                WHERE created_at >= date('now', '-30 days')
                GROUP BY type, severity
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            vulnerability_summary = {
                'total_vulnerabilities': sum(row[2] for row in results),
                'by_severity': {},
                'by_type': {},
                'scan_date': datetime.now().isoformat()
            }
            
            for vuln_type, severity, count in results:
                vulnerability_summary['by_severity'][severity] = vulnerability_summary['by_severity'].get(severity, 0) + count
                vulnerability_summary['by_type'][vuln_type] = vulnerability_summary['by_type'].get(vuln_type, 0) + count
            
            return vulnerability_summary
            
        except Exception as e:
            print(f"Error querying vulnerability database: {e}")
            return {}
    
    def _check_encryption_settings(self) -> Dict[str, Any]:
        """Check encryption configuration settings"""
        # This would integrate with actual system configuration
        # For demonstration, returning mock data
        return {
            'database_encryption': True,
            'file_system_encryption': True,
            'transmission_encryption': True,
            'encryption_algorithms': ['AES-256', 'TLS-1.3'],
            'key_management': 'HSM',
            'checked_at': datetime.now().isoformat()
        }
    
    def _collect_access_logs(self) -> Dict[str, Any]:
        """Collect access logs for compliance"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent access events
            cursor.execute("""
                SELECT user_id, resource, timestamp, COUNT(*) as access_count
                FROM security_events 
                WHERE timestamp >= date('now', '-7 days')
                AND event_type = 'access_request'
                GROUP BY user_id, resource
                ORDER BY access_count DESC
                LIMIT 100
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            access_summary = {
                'total_access_events': sum(row[3] for row in results),
                'unique_users': len(set(row[0] for row in results)),
                'unique_resources': len(set(row[1] for row in results)),
                'top_accessed_resources': [{'resource': row[1], 'count': row[3]} for row in results[:10]],
                'collection_date': datetime.now().isoformat()
            }
            
            return access_summary
            
        except Exception as e:
            print(f"Error collecting access logs: {e}")
            return {}
    
    def _generate_audit_trail(self) -> Dict[str, Any]:
        """Generate audit trail for compliance"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get audit events
            cursor.execute("""
                SELECT event_type, severity, COUNT(*) as count
                FROM security_events 
                WHERE timestamp >= date('now', '-30 days')
                GROUP BY event_type, severity
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            audit_summary = {
                'total_events': sum(row[2] for row in results),
                'by_type': {},
                'by_severity': {},
                'audit_period': '30 days',
                'generated_at': datetime.now().isoformat()
            }
            
            for event_type, severity, count in results:
                audit_summary['by_type'][event_type] = audit_summary['by_type'].get(event_type, 0) + count
                audit_summary['by_severity'][severity] = audit_summary['by_severity'].get(severity, 0) + count
            
            return audit_summary
            
        except Exception as e:
            print(f"Error generating audit trail: {e}")
            return {}
    
    def _perform_network_scan(self) -> Dict[str, Any]:
        """Perform network security scan"""
        # This would integrate with actual network scanning tools
        # For demonstration, returning mock data
        return {
            'open_ports': [22, 80, 443],
            'ssl_configuration': {
                'tls_version': 'TLS 1.3',
                'cipher_suites': ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'],
                'certificate_valid': True
            },
            'firewall_status': 'active',
            'intrusion_detection': 'enabled',
            'scan_date': datetime.now().isoformat()
        }
    
    def _store_evidence(self, evidence: ComplianceEvidence):
        """Store compliance evidence in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO compliance_evidence 
                (evidence_id, requirement_id, evidence_type, description, collected_at, 
                 valid_until, automated, file_path, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.evidence_id,
                evidence.requirement_id,
                evidence.evidence_type,
                evidence.description,
                evidence.collected_at.isoformat(),
                evidence.valid_until.isoformat() if evidence.valid_until else None,
                evidence.automated,
                evidence.file_path,
                json.dumps(evidence.metadata)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error storing evidence: {e}")
    
    def assess_compliance(self, framework: ComplianceFramework) -> ComplianceAssessment:
        """Assess compliance for a specific framework"""
        try:
            requirements = self.requirements.get(framework, [])
            if not requirements:
                raise ValueError(f"No requirements defined for framework: {framework}")
            
            # Collect recent evidence
            self.collect_evidence_automatically()
            
            # Assess each requirement
            compliant_count = 0
            non_compliant_count = 0
            partial_count = 0
            critical_gaps = []
            
            for req in requirements:
                status = self._assess_requirement_compliance(req)
                
                if status == ComplianceStatus.COMPLIANT:
                    compliant_count += 1
                elif status == ComplianceStatus.NON_COMPLIANT:
                    non_compliant_count += 1
                    if req.mandatory and req.penalty_risk in ['high', 'critical']:
                        critical_gaps.append(f"{req.requirement_id}: {req.title}")
                elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
                    partial_count += 1
            
            # Calculate overall compliance score
            total_requirements = len(requirements)
            compliance_score = (compliant_count + (partial_count * 0.5)) / total_requirements
            
            # Determine overall status
            if compliance_score >= 0.95:
                overall_status = ComplianceStatus.COMPLIANT
            elif compliance_score >= 0.8:
                overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
            else:
                overall_status = ComplianceStatus.NON_COMPLIANT
            
            # Generate recommendations
            recommendations = self._generate_compliance_recommendations(framework, requirements, critical_gaps)
            
            # Create assessment
            assessment = ComplianceAssessment(
                assessment_id=hashlib.md5(f"{framework.value}{datetime.now()}".encode()).hexdigest()[:16],
                framework=framework,
                assessed_at=datetime.now(),
                overall_status=overall_status,
                compliance_score=compliance_score,
                requirements_total=total_requirements,
                requirements_compliant=compliant_count,
                requirements_non_compliant=non_compliant_count,
                requirements_partial=partial_count,
                critical_gaps=critical_gaps,
                recommendations=recommendations,
                next_assessment_due=datetime.now() + timedelta(days=90)  # Quarterly assessment
            )
            
            # Store assessment
            self._store_assessment(assessment)
            
            return assessment
            
        except Exception as e:
            print(f"Error assessing compliance: {e}")
            # Return a default assessment indicating error
            return ComplianceAssessment(
                assessment_id="error",
                framework=framework,
                assessed_at=datetime.now(),
                overall_status=ComplianceStatus.UNKNOWN,
                compliance_score=0.0,
                requirements_total=0,
                requirements_compliant=0,
                requirements_non_compliant=0,
                requirements_partial=0,
                critical_gaps=[f"Assessment error: {str(e)}"],
                recommendations=["Fix assessment system errors"],
                next_assessment_due=datetime.now() + timedelta(days=1)
            )
    
    def _assess_requirement_compliance(self, requirement: ComplianceRequirement) -> ComplianceStatus:
        """Assess compliance for a specific requirement"""
        try:
            # Get evidence for this requirement
            evidence = self._get_requirement_evidence(requirement.requirement_id)
            
            if not evidence:
                return ComplianceStatus.NON_COMPLIANT
            
            # Check if evidence is current
            current_evidence = [e for e in evidence if not e.valid_until or e.valid_until > datetime.now()]
            
            if not current_evidence:
                return ComplianceStatus.NON_COMPLIANT
            
            # Assess based on evidence type and requirement
            evidence_types_found = set(e.evidence_type for e in current_evidence)
            required_evidence_types = set(requirement.evidence_required)
            
            if evidence_types_found >= required_evidence_types:
                # All required evidence found - check quality
                return self._assess_evidence_quality(current_evidence, requirement)
            elif len(evidence_types_found) > 0:
                return ComplianceStatus.PARTIALLY_COMPLIANT
            else:
                return ComplianceStatus.NON_COMPLIANT
                
        except Exception as e:
            print(f"Error assessing requirement {requirement.requirement_id}: {e}")
            return ComplianceStatus.UNKNOWN
    
    def _assess_evidence_quality(self, evidence: List[ComplianceEvidence], requirement: ComplianceRequirement) -> ComplianceStatus:
        """Assess the quality of evidence for compliance"""
        # This is a simplified assessment - in production would be more sophisticated
        
        # Check for automated evidence (generally more reliable)
        automated_evidence = [e for e in evidence if e.automated]
        
        # Check evidence freshness
        recent_evidence = [e for e in evidence if (datetime.now() - e.collected_at).days <= 30]
        
        if len(automated_evidence) >= len(requirement.evidence_required) * 0.8 and len(recent_evidence) >= len(evidence) * 0.8:
            return ComplianceStatus.COMPLIANT
        elif len(recent_evidence) >= len(evidence) * 0.5:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            return ComplianceStatus.NON_COMPLIANT
    
    def _get_requirement_evidence(self, requirement_id: str) -> List[ComplianceEvidence]:
        """Get evidence for a specific requirement"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM compliance_evidence 
                WHERE requirement_id = ?
                ORDER BY collected_at DESC
            """, (requirement_id,))
            
            results = cursor.fetchall()
            conn.close()
            
            evidence = []
            for row in results:
                evidence.append(ComplianceEvidence(
                    evidence_id=row[0],
                    requirement_id=row[1],
                    evidence_type=row[2],
                    description=row[3],
                    collected_at=datetime.fromisoformat(row[4]),
                    valid_until=datetime.fromisoformat(row[5]) if row[5] else None,
                    automated=bool(row[6]),
                    file_path=row[7],
                    metadata=json.loads(row[8]) if row[8] else {}
                ))
            
            return evidence
            
        except Exception as e:
            print(f"Error getting evidence for requirement {requirement_id}: {e}")
            return []
    
    def _generate_compliance_recommendations(self, framework: ComplianceFramework, requirements: List[ComplianceRequirement], critical_gaps: List[str]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        if critical_gaps:
            recommendations.append(f"Address {len(critical_gaps)} critical compliance gaps immediately")
            recommendations.extend([f"Priority: {gap}" for gap in critical_gaps[:3]])
        
        # Framework-specific recommendations
        if framework == ComplianceFramework.GDPR:
            recommendations.extend([
                "Implement data subject rights automation",
                "Regular privacy impact assessments",
                "Update privacy policies and notices"
            ])
        elif framework == ComplianceFramework.HIPAA:
            recommendations.extend([
                "Conduct regular risk assessments",
                "Implement workforce training program",
                "Review business associate agreements"
            ])
        elif framework == ComplianceFramework.PCI_DSS:
            recommendations.extend([
                "Regular penetration testing",
                "Implement network segmentation",
                "Update incident response procedures"
            ])
        
        # General recommendations
        recommendations.extend([
            "Automate compliance monitoring where possible",
            "Regular compliance training for staff",
            "Maintain up-to-date documentation"
        ])
        
        return recommendations[:8]  # Limit to top 8
    
    def _store_assessment(self, assessment: ComplianceAssessment):
        """Store compliance assessment in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO compliance_assessments 
                (assessment_id, framework, assessed_at, overall_status, compliance_score,
                 requirements_total, requirements_compliant, requirements_non_compliant,
                 requirements_partial, critical_gaps, recommendations, next_assessment_due)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment.assessment_id,
                assessment.framework.value,
                assessment.assessed_at.isoformat(),
                assessment.overall_status.value,
                assessment.compliance_score,
                assessment.requirements_total,
                assessment.requirements_compliant,
                assessment.requirements_non_compliant,
                assessment.requirements_partial,
                json.dumps(assessment.critical_gaps),
                json.dumps(assessment.recommendations),
                assessment.next_assessment_due.isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error storing assessment: {e}")
    
    def generate_compliance_report(self, framework: ComplianceFramework, assessment_id: str = None) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        try:
            # Get latest assessment or specific assessment
            if assessment_id:
                assessment = self._get_assessment_by_id(assessment_id)
            else:
                assessment = self.assess_compliance(framework)
            
            if not assessment:
                return {'error': 'Assessment not found'}
            
            # Get report template
            template = self.report_templates.get(framework, {})
            
            # Generate report sections
            report = {
                'title': template.get('title', f'{framework.value.upper()} Compliance Report'),
                'generated_at': datetime.now().isoformat(),
                'assessment_id': assessment.assessment_id,
                'framework': framework.value,
                'executive_summary': self._generate_executive_summary(assessment),
                'compliance_overview': {
                    'overall_status': assessment.overall_status.value,
                    'compliance_score': round(assessment.compliance_score * 100, 2),
                    'requirements_total': assessment.requirements_total,
                    'requirements_compliant': assessment.requirements_compliant,
                    'requirements_non_compliant': assessment.requirements_non_compliant,
                    'requirements_partial': assessment.requirements_partial
                },
                'critical_gaps': assessment.critical_gaps,
                'recommendations': assessment.recommendations,
                'detailed_findings': self._generate_detailed_findings(framework, assessment),
                'evidence_summary': self._generate_evidence_summary(framework),
                'next_steps': self._generate_next_steps(assessment),
                'appendices': {
                    'requirements_matrix': self._generate_requirements_matrix(framework),
                    'evidence_inventory': self._generate_evidence_inventory(framework)
                }
            }
            
            return report
            
        except Exception as e:
            return {
                'error': f'Error generating compliance report: {str(e)}',
                'generated_at': datetime.now().isoformat()
            }
    
    def _generate_executive_summary(self, assessment: ComplianceAssessment) -> str:
        """Generate executive summary for compliance report"""
        status_text = {
            ComplianceStatus.COMPLIANT: "fully compliant",
            ComplianceStatus.PARTIALLY_COMPLIANT: "partially compliant",
            ComplianceStatus.NON_COMPLIANT: "non-compliant",
            ComplianceStatus.UNKNOWN: "unknown compliance status"
        }
        
        summary = f"This report presents the results of a {assessment.framework.value.upper()} compliance assessment "
        summary += f"conducted on {assessment.assessed_at.strftime('%B %d, %Y')}. "
        summary += f"The organization is currently {status_text[assessment.overall_status]} "
        summary += f"with a compliance score of {assessment.compliance_score:.1%}. "
        
        if assessment.critical_gaps:
            summary += f"There are {len(assessment.critical_gaps)} critical gaps that require immediate attention. "
        
        summary += f"The next assessment is scheduled for {assessment.next_assessment_due.strftime('%B %d, %Y')}."
        
        return summary
    
    def _generate_detailed_findings(self, framework: ComplianceFramework, assessment: ComplianceAssessment) -> List[Dict]:
        """Generate detailed findings for each requirement"""
        findings = []
        requirements = self.requirements.get(framework, [])
        
        for req in requirements:
            status = self._assess_requirement_compliance(req)
            evidence = self._get_requirement_evidence(req.requirement_id)
            
            finding = {
                'requirement_id': req.requirement_id,
                'title': req.title,
                'category': req.category,
                'status': status.value,
                'mandatory': req.mandatory,
                'evidence_count': len(evidence),
                'last_evidence_date': max([e.collected_at for e in evidence]).isoformat() if evidence else None,
                'gaps': self._identify_requirement_gaps(req, evidence)
            }
            findings.append(finding)
        
        return findings
    
    def _identify_requirement_gaps(self, requirement: ComplianceRequirement, evidence: List[ComplianceEvidence]) -> List[str]:
        """Identify gaps for a specific requirement"""
        gaps = []
        
        evidence_types_found = set(e.evidence_type for e in evidence)
        required_evidence_types = set(requirement.evidence_required)
        
        missing_evidence = required_evidence_types - evidence_types_found
        if missing_evidence:
            gaps.extend([f"Missing evidence: {et}" for et in missing_evidence])
        
        # Check for outdated evidence
        outdated_evidence = [e for e in evidence if e.valid_until and e.valid_until < datetime.now()]
        if outdated_evidence:
            gaps.append(f"Outdated evidence: {len(outdated_evidence)} items")
        
        return gaps
    
    def _generate_evidence_summary(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Generate evidence summary for the framework"""
        requirements = self.requirements.get(framework, [])
        total_evidence = 0
        automated_evidence = 0
        recent_evidence = 0
        
        for req in requirements:
            evidence = self._get_requirement_evidence(req.requirement_id)
            total_evidence += len(evidence)
            automated_evidence += len([e for e in evidence if e.automated])
            recent_evidence += len([e for e in evidence if (datetime.now() - e.collected_at).days <= 30])
        
        return {
            'total_evidence_items': total_evidence,
            'automated_evidence_items': automated_evidence,
            'recent_evidence_items': recent_evidence,
            'automation_rate': round(automated_evidence / total_evidence * 100, 2) if total_evidence > 0 else 0,
            'freshness_rate': round(recent_evidence / total_evidence * 100, 2) if total_evidence > 0 else 0
        }
    
    def _generate_next_steps(self, assessment: ComplianceAssessment) -> List[str]:
        """Generate next steps based on assessment"""
        next_steps = []
        
        if assessment.critical_gaps:
            next_steps.append("Address critical compliance gaps within 30 days")
        
        if assessment.compliance_score < 0.8:
            next_steps.append("Develop compliance improvement plan")
        
        next_steps.extend([
            "Schedule regular compliance monitoring",
            "Update compliance documentation",
            "Conduct staff training on compliance requirements",
            f"Prepare for next assessment due {assessment.next_assessment_due.strftime('%B %d, %Y')}"
        ])
        
        return next_steps[:5]  # Limit to top 5
    
    def _generate_requirements_matrix(self, framework: ComplianceFramework) -> List[Dict]:
        """Generate requirements compliance matrix"""
        requirements = self.requirements.get(framework, [])
        matrix = []
        
        for req in requirements:
            status = self._assess_requirement_compliance(req)
            evidence = self._get_requirement_evidence(req.requirement_id)
            
            matrix.append({
                'requirement_id': req.requirement_id,
                'title': req.title,
                'category': req.category,
                'mandatory': req.mandatory,
                'status': status.value,
                'evidence_types': req.evidence_required,
                'evidence_collected': len(evidence),
                'automated_check': req.automated_check,
                'penalty_risk': req.penalty_risk
            })
        
        return matrix
    
    def _generate_evidence_inventory(self, framework: ComplianceFramework) -> List[Dict]:
        """Generate evidence inventory for the framework"""
        requirements = self.requirements.get(framework, [])
        inventory = []
        
        for req in requirements:
            evidence = self._get_requirement_evidence(req.requirement_id)
            for e in evidence:
                inventory.append({
                    'evidence_id': e.evidence_id,
                    'requirement_id': e.requirement_id,
                    'evidence_type': e.evidence_type,
                    'collected_at': e.collected_at.isoformat(),
                    'valid_until': e.valid_until.isoformat() if e.valid_until else None,
                    'automated': e.automated,
                    'description': e.description
                })
        
        return inventory
    
    def _get_assessment_by_id(self, assessment_id: str) -> Optional[ComplianceAssessment]:
        """Get assessment by ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM compliance_assessments 
                WHERE assessment_id = ?
            """, (assessment_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return ComplianceAssessment(
                    assessment_id=result[0],
                    framework=ComplianceFramework(result[1]),
                    assessed_at=datetime.fromisoformat(result[2]),
                    overall_status=ComplianceStatus(result[3]),
                    compliance_score=result[4],
                    requirements_total=result[5],
                    requirements_compliant=result[6],
                    requirements_non_compliant=result[7],
                    requirements_partial=result[8],
                    critical_gaps=json.loads(result[9]),
                    recommendations=json.loads(result[10]),
                    next_assessment_due=datetime.fromisoformat(result[11])
                )
            
            return None
            
        except Exception as e:
            print(f"Error getting assessment: {e}")
            return None
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Get compliance dashboard data"""
        try:
            dashboard = {
                'frameworks': {},
                'overall_status': 'unknown',
                'total_requirements': 0,
                'compliant_requirements': 0,
                'critical_gaps': 0,
                'last_updated': datetime.now().isoformat()
            }
            
            # Get latest assessments for each framework
            for framework in ComplianceFramework:
                try:
                    assessment = self.assess_compliance(framework)
                    dashboard['frameworks'][framework.value] = {
                        'status': assessment.overall_status.value,
                        'score': round(assessment.compliance_score * 100, 2),
                        'critical_gaps': len(assessment.critical_gaps),
                        'last_assessed': assessment.assessed_at.isoformat()
                    }
                    
                    dashboard['total_requirements'] += assessment.requirements_total
                    dashboard['compliant_requirements'] += assessment.requirements_compliant
                    dashboard['critical_gaps'] += len(assessment.critical_gaps)
                    
                except Exception as e:
                    print(f"Error assessing {framework.value}: {e}")
                    dashboard['frameworks'][framework.value] = {
                        'status': 'error',
                        'score': 0,
                        'critical_gaps': 0,
                        'last_assessed': None
                    }
            
            # Calculate overall status
            if dashboard['total_requirements'] > 0:
                overall_compliance = dashboard['compliant_requirements'] / dashboard['total_requirements']
                if overall_compliance >= 0.9:
                    dashboard['overall_status'] = 'compliant'
                elif overall_compliance >= 0.7:
                    dashboard['overall_status'] = 'partially_compliant'
                else:
                    dashboard['overall_status'] = 'non_compliant'
            
            return dashboard
            
        except Exception as e:
            return {
                'error': f'Error generating compliance dashboard: {str(e)}',
                'last_updated': datetime.now().isoformat()
            }

