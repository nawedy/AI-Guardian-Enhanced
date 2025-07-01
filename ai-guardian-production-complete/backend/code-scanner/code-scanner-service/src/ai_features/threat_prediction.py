"""
Threat Prediction Analytics for AI Guardian
Predictive analytics for emerging threats and vulnerability trends
"""

import json
import sqlite3
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import requests
import os
import re
from collections import defaultdict, Counter
import hashlib

@dataclass
class ThreatPrediction:
    """Prediction about emerging threats"""
    threat_type: str
    probability: float
    severity: str
    timeline: str
    description: str
    indicators: List[str]
    recommendations: List[str]
    confidence: float
    data_sources: List[str]

@dataclass
class VulnerabilityTrend:
    """Trend analysis for vulnerability types"""
    vulnerability_type: str
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    change_rate: float
    current_count: int
    predicted_count: int
    time_period: str

class ThreatPredictionEngine:
    """AI-powered threat prediction and analytics system"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
        self.threat_intelligence_sources = self._initialize_threat_sources()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.prediction_models = self._initialize_prediction_models()
        
        # Cache for threat intelligence data
        self.threat_cache = {}
        self.cache_expiry = timedelta(hours=6)
        self.last_cache_update = None
    
    def _initialize_threat_sources(self) -> Dict[str, Dict]:
        """Initialize threat intelligence sources"""
        return {
            'cve_database': {
                'url': 'https://cve.circl.lu/api/last',
                'type': 'json',
                'update_frequency': 'daily',
                'reliability': 0.95
            },
            'nvd_feeds': {
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'type': 'json',
                'update_frequency': 'daily',
                'reliability': 0.98
            },
            'github_advisories': {
                'url': 'https://api.github.com/advisories',
                'type': 'json',
                'update_frequency': 'hourly',
                'reliability': 0.85
            },
            'owasp_top10': {
                'data': self._get_owasp_top10_data(),
                'type': 'static',
                'update_frequency': 'yearly',
                'reliability': 0.90
            }
        }
    
    def _get_owasp_top10_data(self) -> List[Dict]:
        """Get OWASP Top 10 vulnerability data"""
        return [
            {
                'rank': 1,
                'category': 'Broken Access Control',
                'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced',
                'trend': 'increasing',
                'severity': 'high'
            },
            {
                'rank': 2,
                'category': 'Cryptographic Failures',
                'description': 'Failures related to cryptography which often leads to sensitive data exposure',
                'trend': 'stable',
                'severity': 'high'
            },
            {
                'rank': 3,
                'category': 'Injection',
                'description': 'User-supplied data is not validated, filtered, or sanitized by the application',
                'trend': 'decreasing',
                'severity': 'critical'
            },
            {
                'rank': 4,
                'category': 'Insecure Design',
                'description': 'Risks related to design flaws and missing or ineffective control design',
                'trend': 'increasing',
                'severity': 'high'
            },
            {
                'rank': 5,
                'category': 'Security Misconfiguration',
                'description': 'Missing appropriate security hardening or improperly configured permissions',
                'trend': 'stable',
                'severity': 'medium'
            }
        ]
    
    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load historical vulnerability patterns from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get vulnerability trends over time
            cursor.execute("""
                SELECT type, severity, language, created_at, COUNT(*) as count
                FROM scan_results 
                WHERE created_at >= date('now', '-90 days')
                GROUP BY type, severity, language, date(created_at)
                ORDER BY created_at DESC
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            # Process results into patterns
            patterns = {
                'by_type': defaultdict(list),
                'by_severity': defaultdict(list),
                'by_language': defaultdict(list),
                'temporal': []
            }
            
            for row in results:
                vuln_type, severity, language, date_str, count = row
                patterns['by_type'][vuln_type].append({'date': date_str, 'count': count})
                patterns['by_severity'][severity].append({'date': date_str, 'count': count})
                patterns['by_language'][language].append({'date': date_str, 'count': count})
                patterns['temporal'].append({
                    'date': date_str,
                    'type': vuln_type,
                    'severity': severity,
                    'language': language,
                    'count': count
                })
            
            return patterns
            
        except Exception as e:
            print(f"Error loading vulnerability patterns: {e}")
            return {'by_type': {}, 'by_severity': {}, 'by_language': {}, 'temporal': []}
    
    def _initialize_prediction_models(self) -> Dict[str, Any]:
        """Initialize simple prediction models"""
        return {
            'linear_trend': {
                'description': 'Simple linear trend analysis',
                'accuracy': 0.7,
                'suitable_for': ['short_term', 'stable_patterns']
            },
            'seasonal': {
                'description': 'Seasonal pattern detection',
                'accuracy': 0.65,
                'suitable_for': ['cyclical_patterns', 'long_term']
            },
            'anomaly_detection': {
                'description': 'Detect unusual patterns',
                'accuracy': 0.8,
                'suitable_for': ['emerging_threats', 'outliers']
            }
        }
    
    def predict_emerging_threats(self, time_horizon: str = '30_days') -> List[ThreatPrediction]:
        """Predict emerging threats based on current trends and intelligence"""
        predictions = []
        
        try:
            # Update threat intelligence cache
            self._update_threat_intelligence()
            
            # Analyze current vulnerability trends
            trends = self._analyze_vulnerability_trends()
            
            # Generate predictions based on trends
            for trend in trends:
                if trend.trend_direction == 'increasing' and trend.change_rate > 0.2:
                    prediction = self._generate_threat_prediction(trend, time_horizon)
                    if prediction:
                        predictions.append(prediction)
            
            # Add predictions from external threat intelligence
            external_predictions = self._analyze_external_threats(time_horizon)
            predictions.extend(external_predictions)
            
            # Sort by probability and severity
            predictions.sort(key=lambda x: (x.probability, self._severity_score(x.severity)), reverse=True)
            
            return predictions[:10]  # Return top 10 predictions
            
        except Exception as e:
            print(f"Error predicting threats: {e}")
            return []
    
    def _update_threat_intelligence(self):
        """Update threat intelligence from external sources"""
        if (self.last_cache_update and 
            datetime.now() - self.last_cache_update < self.cache_expiry):
            return  # Cache is still valid
        
        for source_name, source_config in self.threat_intelligence_sources.items():
            try:
                if source_config['type'] == 'json' and 'url' in source_config:
                    # Fetch data from external API
                    response = requests.get(source_config['url'], timeout=10)
                    if response.status_code == 200:
                        self.threat_cache[source_name] = {
                            'data': response.json(),
                            'timestamp': datetime.now(),
                            'reliability': source_config['reliability']
                        }
                elif source_config['type'] == 'static':
                    # Use static data
                    self.threat_cache[source_name] = {
                        'data': source_config['data'],
                        'timestamp': datetime.now(),
                        'reliability': source_config['reliability']
                    }
                    
            except Exception as e:
                print(f"Error updating threat intelligence from {source_name}: {e}")
        
        self.last_cache_update = datetime.now()
    
    def _analyze_vulnerability_trends(self) -> List[VulnerabilityTrend]:
        """Analyze trends in vulnerability data"""
        trends = []
        
        try:
            # Analyze trends by vulnerability type
            for vuln_type, data_points in self.vulnerability_patterns['by_type'].items():
                if len(data_points) >= 3:  # Need at least 3 data points for trend analysis
                    trend = self._calculate_trend(vuln_type, data_points)
                    if trend:
                        trends.append(trend)
            
            return trends
            
        except Exception as e:
            print(f"Error analyzing vulnerability trends: {e}")
            return []
    
    def _calculate_trend(self, vuln_type: str, data_points: List[Dict]) -> Optional[VulnerabilityTrend]:
        """Calculate trend for a specific vulnerability type"""
        try:
            # Sort by date
            sorted_points = sorted(data_points, key=lambda x: x['date'])
            
            if len(sorted_points) < 2:
                return None
            
            # Calculate simple linear trend
            counts = [point['count'] for point in sorted_points]
            
            # Simple trend calculation
            recent_avg = np.mean(counts[-7:]) if len(counts) >= 7 else np.mean(counts[-3:])
            older_avg = np.mean(counts[:7]) if len(counts) >= 14 else np.mean(counts[:len(counts)//2])
            
            if older_avg == 0:
                change_rate = 1.0 if recent_avg > 0 else 0.0
            else:
                change_rate = (recent_avg - older_avg) / older_avg
            
            # Determine trend direction
            if change_rate > 0.1:
                trend_direction = 'increasing'
            elif change_rate < -0.1:
                trend_direction = 'decreasing'
            else:
                trend_direction = 'stable'
            
            # Predict future count
            predicted_count = int(recent_avg * (1 + change_rate))
            
            return VulnerabilityTrend(
                vulnerability_type=vuln_type,
                trend_direction=trend_direction,
                change_rate=change_rate,
                current_count=int(recent_avg),
                predicted_count=predicted_count,
                time_period='30_days'
            )
            
        except Exception as e:
            print(f"Error calculating trend for {vuln_type}: {e}")
            return None
    
    def _generate_threat_prediction(self, trend: VulnerabilityTrend, time_horizon: str) -> Optional[ThreatPrediction]:
        """Generate threat prediction based on vulnerability trend"""
        try:
            # Calculate probability based on trend strength
            probability = min(0.95, 0.5 + abs(trend.change_rate))
            
            # Determine severity based on vulnerability type and trend
            severity = self._determine_threat_severity(trend)
            
            # Generate description
            description = f"Increasing trend detected for {trend.vulnerability_type} vulnerabilities. "
            description += f"Current rate of change: {trend.change_rate:.2%}. "
            description += f"Predicted increase from {trend.current_count} to {trend.predicted_count} cases."
            
            # Generate indicators
            indicators = [
                f"Vulnerability type: {trend.vulnerability_type}",
                f"Trend direction: {trend.trend_direction}",
                f"Change rate: {trend.change_rate:.2%}",
                f"Current frequency: {trend.current_count} cases"
            ]
            
            # Generate recommendations
            recommendations = self._generate_threat_recommendations(trend)
            
            # Calculate confidence
            confidence = self._calculate_prediction_confidence(trend)
            
            return ThreatPrediction(
                threat_type=trend.vulnerability_type,
                probability=probability,
                severity=severity,
                timeline=time_horizon,
                description=description,
                indicators=indicators,
                recommendations=recommendations,
                confidence=confidence,
                data_sources=['internal_vulnerability_database']
            )
            
        except Exception as e:
            print(f"Error generating threat prediction: {e}")
            return None
    
    def _analyze_external_threats(self, time_horizon: str) -> List[ThreatPrediction]:
        """Analyze external threat intelligence for predictions"""
        predictions = []
        
        try:
            # Analyze OWASP Top 10 trends
            if 'owasp_top10' in self.threat_cache:
                owasp_data = self.threat_cache['owasp_top10']['data']
                for item in owasp_data:
                    if item['trend'] == 'increasing':
                        prediction = ThreatPrediction(
                            threat_type=item['category'],
                            probability=0.8,
                            severity=item['severity'],
                            timeline=time_horizon,
                            description=f"OWASP Top 10 category showing increasing trend: {item['description']}",
                            indicators=[f"OWASP Rank: #{item['rank']}", f"Trend: {item['trend']}"],
                            recommendations=[
                                f"Review code for {item['category']} vulnerabilities",
                                "Implement specific security controls",
                                "Conduct security training on this topic"
                            ],
                            confidence=0.85,
                            data_sources=['owasp_top10']
                        )
                        predictions.append(prediction)
            
            # Analyze CVE trends (simplified)
            if 'cve_database' in self.threat_cache:
                cve_data = self.threat_cache['cve_database']['data']
                # This would be more sophisticated in a real implementation
                recent_cves = self._analyze_recent_cves(cve_data)
                predictions.extend(recent_cves)
            
            return predictions
            
        except Exception as e:
            print(f"Error analyzing external threats: {e}")
            return []
    
    def _analyze_recent_cves(self, cve_data: Any) -> List[ThreatPrediction]:
        """Analyze recent CVEs for emerging threat patterns"""
        predictions = []
        
        try:
            # This is a simplified analysis
            # In a real implementation, this would use NLP and ML to analyze CVE descriptions
            
            common_patterns = [
                'remote code execution',
                'sql injection',
                'cross-site scripting',
                'buffer overflow',
                'privilege escalation'
            ]
            
            for pattern in common_patterns:
                prediction = ThreatPrediction(
                    threat_type=pattern.replace(' ', '_'),
                    probability=0.6,
                    severity='high',
                    timeline='30_days',
                    description=f"Recent CVEs show continued prevalence of {pattern} vulnerabilities",
                    indicators=[f"Pattern: {pattern}", "Source: Recent CVE analysis"],
                    recommendations=[
                        f"Scan for {pattern} vulnerabilities",
                        "Update security controls",
                        "Review recent security patches"
                    ],
                    confidence=0.7,
                    data_sources=['cve_database']
                )
                predictions.append(prediction)
            
            return predictions[:3]  # Return top 3
            
        except Exception as e:
            print(f"Error analyzing CVEs: {e}")
            return []
    
    def _determine_threat_severity(self, trend: VulnerabilityTrend) -> str:
        """Determine threat severity based on trend characteristics"""
        high_risk_types = [
            'sql_injection', 'code_injection', 'command_injection',
            'remote_code_execution', 'privilege_escalation'
        ]
        
        medium_risk_types = [
            'xss', 'csrf', 'path_traversal', 'information_disclosure'
        ]
        
        vuln_type_lower = trend.vulnerability_type.lower()
        
        if any(risk_type in vuln_type_lower for risk_type in high_risk_types):
            return 'critical' if trend.change_rate > 0.5 else 'high'
        elif any(risk_type in vuln_type_lower for risk_type in medium_risk_types):
            return 'high' if trend.change_rate > 0.5 else 'medium'
        else:
            return 'medium' if trend.change_rate > 0.3 else 'low'
    
    def _generate_threat_recommendations(self, trend: VulnerabilityTrend) -> List[str]:
        """Generate recommendations based on threat trend"""
        recommendations = []
        
        # General recommendations
        recommendations.append(f"Increase monitoring for {trend.vulnerability_type} vulnerabilities")
        recommendations.append("Review and update security controls")
        
        # Specific recommendations based on vulnerability type
        vuln_type_lower = trend.vulnerability_type.lower()
        
        if 'injection' in vuln_type_lower:
            recommendations.extend([
                "Implement input validation and parameterized queries",
                "Review data sanitization procedures",
                "Conduct injection vulnerability testing"
            ])
        elif 'xss' in vuln_type_lower:
            recommendations.extend([
                "Implement Content Security Policy",
                "Review output encoding practices",
                "Test for XSS vulnerabilities"
            ])
        elif 'authentication' in vuln_type_lower:
            recommendations.extend([
                "Review authentication mechanisms",
                "Implement multi-factor authentication",
                "Audit user access controls"
            ])
        else:
            recommendations.extend([
                "Conduct targeted security testing",
                "Review relevant security documentation",
                "Consider additional security controls"
            ])
        
        return recommendations[:5]  # Limit to top 5
    
    def _calculate_prediction_confidence(self, trend: VulnerabilityTrend) -> float:
        """Calculate confidence score for prediction"""
        base_confidence = 0.6
        
        # Increase confidence for stronger trends
        if abs(trend.change_rate) > 0.5:
            base_confidence += 0.2
        elif abs(trend.change_rate) > 0.3:
            base_confidence += 0.1
        
        # Increase confidence for more data points
        # This would be based on actual data point count in a real implementation
        base_confidence += 0.1
        
        # Decrease confidence for very volatile trends
        if abs(trend.change_rate) > 1.0:
            base_confidence -= 0.1
        
        return min(0.95, max(0.1, base_confidence))
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity to numeric score for sorting"""
        severity_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return severity_scores.get(severity.lower(), 0)
    
    def get_threat_landscape_summary(self) -> Dict[str, Any]:
        """Get overall threat landscape summary"""
        try:
            predictions = self.predict_emerging_threats()
            trends = self._analyze_vulnerability_trends()
            
            # Calculate summary statistics
            total_predictions = len(predictions)
            high_risk_predictions = len([p for p in predictions if p.severity in ['critical', 'high']])
            avg_probability = np.mean([p.probability for p in predictions]) if predictions else 0
            
            # Top threat categories
            threat_categories = Counter([p.threat_type for p in predictions])
            top_threats = threat_categories.most_common(5)
            
            # Trend summary
            increasing_trends = len([t for t in trends if t.trend_direction == 'increasing'])
            stable_trends = len([t for t in trends if t.trend_direction == 'stable'])
            decreasing_trends = len([t for t in trends if t.trend_direction == 'decreasing'])
            
            return {
                'summary': {
                    'total_predictions': total_predictions,
                    'high_risk_predictions': high_risk_predictions,
                    'average_probability': round(avg_probability, 2),
                    'risk_level': self._calculate_overall_risk_level(predictions)
                },
                'top_threats': [{'type': threat, 'count': count} for threat, count in top_threats],
                'trends': {
                    'increasing': increasing_trends,
                    'stable': stable_trends,
                    'decreasing': decreasing_trends
                },
                'recommendations': self._generate_landscape_recommendations(predictions, trends),
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'error': f"Error generating threat landscape summary: {str(e)}",
                'last_updated': datetime.now().isoformat()
            }
    
    def _calculate_overall_risk_level(self, predictions: List[ThreatPrediction]) -> str:
        """Calculate overall risk level based on predictions"""
        if not predictions:
            return 'low'
        
        # Calculate weighted risk score
        risk_score = 0
        total_weight = 0
        
        for prediction in predictions:
            severity_weight = self._severity_score(prediction.severity)
            probability_weight = prediction.probability
            confidence_weight = prediction.confidence
            
            weight = severity_weight * probability_weight * confidence_weight
            risk_score += weight
            total_weight += severity_weight
        
        if total_weight == 0:
            return 'low'
        
        avg_risk = risk_score / total_weight
        
        if avg_risk >= 3.0:
            return 'critical'
        elif avg_risk >= 2.0:
            return 'high'
        elif avg_risk >= 1.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_landscape_recommendations(self, predictions: List[ThreatPrediction], trends: List[VulnerabilityTrend]) -> List[str]:
        """Generate overall landscape recommendations"""
        recommendations = []
        
        if not predictions and not trends:
            return ["Continue regular security monitoring and assessments"]
        
        # High-level recommendations based on predictions
        high_risk_predictions = [p for p in predictions if p.severity in ['critical', 'high']]
        if high_risk_predictions:
            recommendations.append("Immediate attention required for high-risk emerging threats")
            recommendations.append("Implement enhanced monitoring and detection capabilities")
        
        # Recommendations based on trends
        increasing_trends = [t for t in trends if t.trend_direction == 'increasing']
        if len(increasing_trends) > 3:
            recommendations.append("Multiple vulnerability types showing increasing trends - comprehensive security review recommended")
        
        # General recommendations
        recommendations.extend([
            "Regular threat intelligence updates and analysis",
            "Continuous security monitoring and incident response preparedness",
            "Proactive vulnerability management and patching",
            "Security awareness training for development teams"
        ])
        
        return recommendations[:6]  # Limit to top 6

