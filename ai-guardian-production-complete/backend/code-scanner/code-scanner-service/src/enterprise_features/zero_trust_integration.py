"""
Zero Trust Integration for AI Guardian
Integration with zero trust security frameworks and principles
"""

import json
import sqlite3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import hashlib
import jwt
import os
from enum import Enum

class TrustLevel(Enum):
    """Trust levels in Zero Trust model"""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4

class AccessDecision(Enum):
    """Access control decisions"""
    DENY = "deny"
    ALLOW = "allow"
    CONDITIONAL = "conditional"
    MONITOR = "monitor"

@dataclass
class ZeroTrustContext:
    """Context information for Zero Trust evaluation"""
    user_id: str
    device_id: str
    location: str
    network: str
    time_of_access: datetime
    resource_requested: str
    risk_score: float
    authentication_method: str
    device_compliance: bool
    network_trust_level: TrustLevel

@dataclass
class AccessPolicy:
    """Zero Trust access policy"""
    policy_id: str
    name: str
    resource_pattern: str
    required_trust_level: TrustLevel
    conditions: List[Dict[str, Any]]
    actions: List[str]
    monitoring_required: bool
    valid_until: Optional[datetime]

@dataclass
class SecurityEvent:
    """Security event for Zero Trust monitoring"""
    event_id: str
    event_type: str
    severity: str
    user_id: str
    device_id: str
    resource: str
    description: str
    timestamp: datetime
    context: Dict[str, Any]

class ZeroTrustIntegration:
    """Zero Trust security framework integration"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
        self.policies = self._load_access_policies()
        self.trust_algorithms = self._initialize_trust_algorithms()
        self.security_events = []
        
        # Zero Trust principles configuration
        self.zt_config = {
            'never_trust_always_verify': True,
            'least_privilege_access': True,
            'assume_breach': True,
            'continuous_monitoring': True,
            'micro_segmentation': True,
            'encryption_everywhere': True
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'user_behavior': 0.25,
            'device_compliance': 0.20,
            'network_location': 0.15,
            'time_anomaly': 0.10,
            'resource_sensitivity': 0.15,
            'authentication_strength': 0.15
        }
    
    def _load_access_policies(self) -> List[AccessPolicy]:
        """Load Zero Trust access policies"""
        default_policies = [
            AccessPolicy(
                policy_id="zt_001",
                name="Critical Code Access",
                resource_pattern="*/critical/*",
                required_trust_level=TrustLevel.VERIFIED,
                conditions=[
                    {"type": "mfa_required", "value": True},
                    {"type": "device_compliance", "value": True},
                    {"type": "network_trust", "min_level": "high"}
                ],
                actions=["log", "monitor", "require_approval"],
                monitoring_required=True,
                valid_until=None
            ),
            AccessPolicy(
                policy_id="zt_002",
                name="Production Environment",
                resource_pattern="*/production/*",
                required_trust_level=TrustLevel.HIGH,
                conditions=[
                    {"type": "business_hours", "value": True},
                    {"type": "approved_location", "value": True},
                    {"type": "device_managed", "value": True}
                ],
                actions=["log", "monitor"],
                monitoring_required=True,
                valid_until=None
            ),
            AccessPolicy(
                policy_id="zt_003",
                name="Security Scanning Tools",
                resource_pattern="*/scanner/*",
                required_trust_level=TrustLevel.MEDIUM,
                conditions=[
                    {"type": "authenticated", "value": True},
                    {"type": "role", "values": ["security_analyst", "developer", "admin"]}
                ],
                actions=["log"],
                monitoring_required=True,
                valid_until=None
            ),
            AccessPolicy(
                policy_id="zt_004",
                name="AI Features Access",
                resource_pattern="*/ai/*",
                required_trust_level=TrustLevel.MEDIUM,
                conditions=[
                    {"type": "authenticated", "value": True},
                    {"type": "api_key_valid", "value": True},
                    {"type": "rate_limit", "max_requests": 100}
                ],
                actions=["log", "rate_limit"],
                monitoring_required=True,
                valid_until=None
            )
        ]
        
        return default_policies
    
    def _initialize_trust_algorithms(self) -> Dict[str, Any]:
        """Initialize trust calculation algorithms"""
        return {
            'user_behavior': {
                'normal_hours': (8, 18),  # 8 AM to 6 PM
                'normal_locations': ['office', 'home_office'],
                'suspicious_patterns': ['off_hours_bulk_access', 'unusual_location', 'rapid_resource_access']
            },
            'device_compliance': {
                'required_features': ['encryption', 'antivirus', 'firewall', 'updated_os'],
                'prohibited_features': ['jailbreak', 'root_access', 'debug_mode']
            },
            'network_trust': {
                'trusted_networks': ['corporate_vpn', 'office_network'],
                'untrusted_networks': ['public_wifi', 'unknown_network'],
                'suspicious_indicators': ['tor_exit_node', 'known_malicious_ip', 'geo_anomaly']
            }
        }
    
    def evaluate_access_request(self, context: ZeroTrustContext) -> Tuple[AccessDecision, float, List[str]]:
        """Evaluate access request using Zero Trust principles"""
        try:
            # Calculate trust score
            trust_score = self._calculate_trust_score(context)
            
            # Find applicable policies
            applicable_policies = self._find_applicable_policies(context.resource_requested)
            
            # Evaluate against policies
            decision, reasons = self._evaluate_policies(context, applicable_policies, trust_score)
            
            # Log security event
            self._log_security_event(context, decision, trust_score, reasons)
            
            return decision, trust_score, reasons
            
        except Exception as e:
            # Fail secure - deny access on error
            error_reason = f"Error evaluating access: {str(e)}"
            self._log_security_event(context, AccessDecision.DENY, 0.0, [error_reason])
            return AccessDecision.DENY, 0.0, [error_reason]
    
    def _calculate_trust_score(self, context: ZeroTrustContext) -> float:
        """Calculate overall trust score based on context"""
        scores = {}
        
        # User behavior score
        scores['user_behavior'] = self._calculate_user_behavior_score(context)
        
        # Device compliance score
        scores['device_compliance'] = 1.0 if context.device_compliance else 0.0
        
        # Network location score
        scores['network_location'] = self._calculate_network_trust_score(context)
        
        # Time anomaly score
        scores['time_anomaly'] = self._calculate_time_anomaly_score(context)
        
        # Resource sensitivity score
        scores['resource_sensitivity'] = self._calculate_resource_sensitivity_score(context)
        
        # Authentication strength score
        scores['authentication_strength'] = self._calculate_auth_strength_score(context)
        
        # Calculate weighted average
        total_score = 0.0
        for factor, score in scores.items():
            weight = self.risk_weights.get(factor, 0.0)
            total_score += score * weight
        
        return min(1.0, max(0.0, total_score))
    
    def _calculate_user_behavior_score(self, context: ZeroTrustContext) -> float:
        """Calculate user behavior trust score"""
        score = 0.8  # Base score
        
        # Check access time
        current_hour = context.time_of_access.hour
        normal_start, normal_end = self.trust_algorithms['user_behavior']['normal_hours']
        
        if normal_start <= current_hour <= normal_end:
            score += 0.1
        else:
            score -= 0.2  # Penalty for off-hours access
        
        # Check location patterns
        if context.location in self.trust_algorithms['user_behavior']['normal_locations']:
            score += 0.1
        
        # Check for suspicious patterns (would be based on historical data)
        # This is simplified - in reality would analyze user's historical patterns
        
        return min(1.0, max(0.0, score))
    
    def _calculate_network_trust_score(self, context: ZeroTrustContext) -> float:
        """Calculate network trust score"""
        trusted_networks = self.trust_algorithms['network_trust']['trusted_networks']
        untrusted_networks = self.trust_algorithms['network_trust']['untrusted_networks']
        
        if context.network in trusted_networks:
            return 0.9
        elif context.network in untrusted_networks:
            return 0.2
        else:
            return 0.5  # Unknown network - medium trust
    
    def _calculate_time_anomaly_score(self, context: ZeroTrustContext) -> float:
        """Calculate time-based anomaly score"""
        # Check if access time is within normal business hours
        current_hour = context.time_of_access.hour
        current_day = context.time_of_access.weekday()  # 0 = Monday, 6 = Sunday
        
        # Business hours: Monday-Friday, 8 AM - 6 PM
        if 0 <= current_day <= 4 and 8 <= current_hour <= 18:
            return 0.9
        elif 0 <= current_day <= 4:  # Weekday but off hours
            return 0.6
        else:  # Weekend
            return 0.4
    
    def _calculate_resource_sensitivity_score(self, context: ZeroTrustContext) -> float:
        """Calculate resource sensitivity score"""
        resource = context.resource_requested.lower()
        
        # High sensitivity resources
        if any(pattern in resource for pattern in ['critical', 'production', 'admin', 'config']):
            return 0.3  # Lower score for high sensitivity (requires higher trust)
        
        # Medium sensitivity resources
        elif any(pattern in resource for pattern in ['scanner', 'api', 'data']):
            return 0.6
        
        # Low sensitivity resources
        else:
            return 0.9
    
    def _calculate_auth_strength_score(self, context: ZeroTrustContext) -> float:
        """Calculate authentication strength score"""
        auth_method = context.authentication_method.lower()
        
        if 'mfa' in auth_method or 'multi_factor' in auth_method:
            return 0.95
        elif 'certificate' in auth_method or 'pki' in auth_method:
            return 0.9
        elif 'token' in auth_method:
            return 0.7
        elif 'password' in auth_method:
            return 0.5
        else:
            return 0.2  # Unknown or weak authentication
    
    def _find_applicable_policies(self, resource: str) -> List[AccessPolicy]:
        """Find policies applicable to the requested resource"""
        applicable = []
        
        for policy in self.policies:
            # Simple pattern matching - in production would use more sophisticated matching
            pattern = policy.resource_pattern.replace('*', '.*')
            if resource.startswith(pattern.replace('.*', '')):
                applicable.append(policy)
        
        return applicable
    
    def _evaluate_policies(self, context: ZeroTrustContext, policies: List[AccessPolicy], trust_score: float) -> Tuple[AccessDecision, List[str]]:
        """Evaluate context against applicable policies"""
        reasons = []
        most_restrictive_decision = AccessDecision.ALLOW
        
        if not policies:
            # No specific policies - apply default Zero Trust principles
            if trust_score >= 0.7:
                return AccessDecision.ALLOW, ["Default policy: sufficient trust score"]
            elif trust_score >= 0.5:
                return AccessDecision.CONDITIONAL, ["Default policy: conditional access based on trust score"]
            else:
                return AccessDecision.DENY, ["Default policy: insufficient trust score"]
        
        for policy in policies:
            decision, policy_reasons = self._evaluate_single_policy(context, policy, trust_score)
            reasons.extend(policy_reasons)
            
            # Apply most restrictive decision
            if decision == AccessDecision.DENY:
                most_restrictive_decision = AccessDecision.DENY
            elif decision == AccessDecision.CONDITIONAL and most_restrictive_decision != AccessDecision.DENY:
                most_restrictive_decision = AccessDecision.CONDITIONAL
            elif decision == AccessDecision.MONITOR and most_restrictive_decision == AccessDecision.ALLOW:
                most_restrictive_decision = AccessDecision.MONITOR
        
        return most_restrictive_decision, reasons
    
    def _evaluate_single_policy(self, context: ZeroTrustContext, policy: AccessPolicy, trust_score: float) -> Tuple[AccessDecision, List[str]]:
        """Evaluate context against a single policy"""
        reasons = []
        
        # Check if policy is still valid
        if policy.valid_until and datetime.now() > policy.valid_until:
            return AccessDecision.DENY, [f"Policy {policy.name} has expired"]
        
        # Check trust level requirement
        required_trust = policy.required_trust_level.value / 4.0  # Convert to 0-1 scale
        if trust_score < required_trust:
            return AccessDecision.DENY, [f"Insufficient trust level for policy {policy.name}"]
        
        # Evaluate conditions
        for condition in policy.conditions:
            condition_met, reason = self._evaluate_condition(context, condition)
            if not condition_met:
                return AccessDecision.DENY, [f"Policy {policy.name}: {reason}"]
            reasons.append(f"Policy {policy.name}: {reason}")
        
        # Determine final decision based on actions
        if 'require_approval' in policy.actions:
            return AccessDecision.CONDITIONAL, reasons + ["Manual approval required"]
        elif policy.monitoring_required:
            return AccessDecision.MONITOR, reasons + ["Access granted with monitoring"]
        else:
            return AccessDecision.ALLOW, reasons + ["Access granted"]
    
    def _evaluate_condition(self, context: ZeroTrustContext, condition: Dict[str, Any]) -> Tuple[bool, str]:
        """Evaluate a single policy condition"""
        condition_type = condition.get('type')
        
        if condition_type == 'mfa_required':
            required = condition.get('value', True)
            has_mfa = 'mfa' in context.authentication_method.lower()
            return has_mfa == required, f"MFA requirement {'met' if has_mfa == required else 'not met'}"
        
        elif condition_type == 'device_compliance':
            required = condition.get('value', True)
            return context.device_compliance == required, f"Device compliance {'met' if context.device_compliance == required else 'not met'}"
        
        elif condition_type == 'network_trust':
            min_level = condition.get('min_level', 'medium')
            level_map = {'low': 1, 'medium': 2, 'high': 3}
            required_level = level_map.get(min_level, 2)
            actual_level = context.network_trust_level.value
            return actual_level >= required_level, f"Network trust level {'sufficient' if actual_level >= required_level else 'insufficient'}"
        
        elif condition_type == 'business_hours':
            required = condition.get('value', True)
            current_hour = context.time_of_access.hour
            current_day = context.time_of_access.weekday()
            is_business_hours = (0 <= current_day <= 4) and (8 <= current_hour <= 18)
            return is_business_hours == required, f"Business hours requirement {'met' if is_business_hours == required else 'not met'}"
        
        elif condition_type == 'authenticated':
            required = condition.get('value', True)
            is_authenticated = bool(context.user_id and context.authentication_method)
            return is_authenticated == required, f"Authentication requirement {'met' if is_authenticated == required else 'not met'}"
        
        else:
            # Unknown condition type - fail secure
            return False, f"Unknown condition type: {condition_type}"
    
    def _log_security_event(self, context: ZeroTrustContext, decision: AccessDecision, trust_score: float, reasons: List[str]):
        """Log security event for monitoring and analysis"""
        event = SecurityEvent(
            event_id=hashlib.md5(f"{context.user_id}{context.resource_requested}{datetime.now()}".encode()).hexdigest()[:16],
            event_type="access_request",
            severity=self._determine_event_severity(decision, trust_score),
            user_id=context.user_id,
            device_id=context.device_id,
            resource=context.resource_requested,
            description=f"Access {decision.value} for {context.resource_requested}",
            timestamp=datetime.now(),
            context={
                'trust_score': trust_score,
                'decision': decision.value,
                'reasons': reasons,
                'location': context.location,
                'network': context.network,
                'authentication_method': context.authentication_method
            }
        )
        
        self.security_events.append(event)
        
        # In production, this would also write to a security information and event management (SIEM) system
        self._store_security_event(event)
    
    def _determine_event_severity(self, decision: AccessDecision, trust_score: float) -> str:
        """Determine severity of security event"""
        if decision == AccessDecision.DENY:
            return "high" if trust_score < 0.3 else "medium"
        elif decision == AccessDecision.CONDITIONAL:
            return "medium"
        elif trust_score < 0.5:
            return "medium"
        else:
            return "low"
    
    def _store_security_event(self, event: SecurityEvent):
        """Store security event in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create security events table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT,
                    severity TEXT,
                    user_id TEXT,
                    device_id TEXT,
                    resource TEXT,
                    description TEXT,
                    timestamp TEXT,
                    context TEXT
                )
            """)
            
            # Insert event
            cursor.execute("""
                INSERT OR REPLACE INTO security_events 
                (event_id, event_type, severity, user_id, device_id, resource, description, timestamp, context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.event_type,
                event.severity,
                event.user_id,
                event.device_id,
                event.resource,
                event.description,
                event.timestamp.isoformat(),
                json.dumps(event.context)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error storing security event: {e}")
    
    def get_security_events(self, time_range: timedelta = None, severity: str = None) -> List[SecurityEvent]:
        """Retrieve security events with optional filtering"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []
            
            if time_range:
                since = datetime.now() - time_range
                query += " AND timestamp >= ?"
                params.append(since.isoformat())
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            query += " ORDER BY timestamp DESC LIMIT 1000"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
            events = []
            for row in results:
                event = SecurityEvent(
                    event_id=row[0],
                    event_type=row[1],
                    severity=row[2],
                    user_id=row[3],
                    device_id=row[4],
                    resource=row[5],
                    description=row[6],
                    timestamp=datetime.fromisoformat(row[7]),
                    context=json.loads(row[8])
                )
                events.append(event)
            
            return events
            
        except Exception as e:
            print(f"Error retrieving security events: {e}")
            return []
    
    def generate_zero_trust_report(self) -> Dict[str, Any]:
        """Generate Zero Trust security posture report"""
        try:
            # Get recent events
            recent_events = self.get_security_events(timedelta(days=7))
            
            # Calculate statistics
            total_requests = len(recent_events)
            denied_requests = len([e for e in recent_events if 'deny' in e.context.get('decision', '')])
            conditional_requests = len([e for e in recent_events if 'conditional' in e.context.get('decision', '')])
            
            # Calculate average trust scores
            trust_scores = [e.context.get('trust_score', 0) for e in recent_events if 'trust_score' in e.context]
            avg_trust_score = sum(trust_scores) / len(trust_scores) if trust_scores else 0
            
            # Identify top risks
            high_severity_events = [e for e in recent_events if e.severity == 'high']
            
            # Policy compliance
            policy_violations = denied_requests
            
            report = {
                'report_period': '7 days',
                'generated_at': datetime.now().isoformat(),
                'summary': {
                    'total_access_requests': total_requests,
                    'denied_requests': denied_requests,
                    'conditional_requests': conditional_requests,
                    'approval_rate': round((total_requests - denied_requests) / total_requests * 100, 2) if total_requests > 0 else 0,
                    'average_trust_score': round(avg_trust_score, 2)
                },
                'security_posture': {
                    'risk_level': self._calculate_overall_risk_level(recent_events),
                    'policy_compliance': round((total_requests - policy_violations) / total_requests * 100, 2) if total_requests > 0 else 100,
                    'high_risk_events': len(high_severity_events)
                },
                'recommendations': self._generate_zt_recommendations(recent_events),
                'top_risks': [
                    {
                        'event_id': e.event_id,
                        'description': e.description,
                        'severity': e.severity,
                        'timestamp': e.timestamp.isoformat()
                    } for e in high_severity_events[:5]
                ]
            }
            
            return report
            
        except Exception as e:
            return {
                'error': f"Error generating Zero Trust report: {str(e)}",
                'generated_at': datetime.now().isoformat()
            }
    
    def _calculate_overall_risk_level(self, events: List[SecurityEvent]) -> str:
        """Calculate overall risk level based on recent events"""
        if not events:
            return 'low'
        
        high_severity_count = len([e for e in events if e.severity == 'high'])
        medium_severity_count = len([e for e in events if e.severity == 'medium'])
        
        total_events = len(events)
        high_severity_ratio = high_severity_count / total_events
        medium_severity_ratio = medium_severity_count / total_events
        
        if high_severity_ratio > 0.1:  # More than 10% high severity
            return 'high'
        elif high_severity_ratio > 0.05 or medium_severity_ratio > 0.3:
            return 'medium'
        else:
            return 'low'
    
    def _generate_zt_recommendations(self, events: List[SecurityEvent]) -> List[str]:
        """Generate Zero Trust recommendations based on events"""
        recommendations = []
        
        if not events:
            return ["Continue monitoring and maintain current security posture"]
        
        # Analyze patterns
        denied_events = [e for e in events if 'deny' in e.context.get('decision', '')]
        off_hours_events = [e for e in events if e.timestamp.hour < 8 or e.timestamp.hour > 18]
        
        if len(denied_events) > len(events) * 0.1:
            recommendations.append("High number of denied access requests - review and update access policies")
        
        if len(off_hours_events) > len(events) * 0.2:
            recommendations.append("Significant off-hours activity detected - consider implementing stricter time-based controls")
        
        # Device compliance issues
        non_compliant_events = [e for e in events if not e.context.get('device_compliance', True)]
        if non_compliant_events:
            recommendations.append("Non-compliant devices detected - enforce device compliance policies")
        
        # Network trust issues
        untrusted_network_events = [e for e in events if e.context.get('network_trust_level', 2) < 2]
        if untrusted_network_events:
            recommendations.append("Access from untrusted networks detected - consider network segmentation")
        
        # General recommendations
        recommendations.extend([
            "Regular review and update of Zero Trust policies",
            "Continuous monitoring and analysis of access patterns",
            "User training on Zero Trust security principles"
        ])
        
        return recommendations[:5]  # Limit to top 5

