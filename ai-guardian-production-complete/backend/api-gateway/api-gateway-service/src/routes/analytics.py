"""
Advanced Analytics Service for AI Guardian
Provides comprehensive security analytics, reporting, and insights
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
import json
import logging
from collections import defaultdict, Counter
import sqlite3
import os
from dataclasses import dataclass
import plotly.graph_objects as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder
import io
import base64

analytics_bp = Blueprint('analytics', __name__)

@dataclass
class SecurityMetric:
    """Security metric data structure"""
    name: str
    value: float
    unit: str
    trend: str  # 'up', 'down', 'stable'
    change_percentage: float
    timestamp: datetime

@dataclass
class VulnerabilityTrend:
    """Vulnerability trend data structure"""
    date: datetime
    critical: int
    high: int
    medium: int
    low: int
    total: int

class AdvancedAnalyticsService:
    """Advanced analytics and reporting service"""
    
    def __init__(self):
        self.db_path = os.getenv('ANALYTICS_DB_PATH', '/app/data/analytics.db')
        self.retention_days = int(os.getenv('ANALYTICS_RETENTION_DAYS', '365'))
        self._init_database()
    
    def _init_database(self):
        """Initialize analytics database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Vulnerability events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerability_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        vulnerability_id TEXT NOT NULL,
                        vulnerability_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        language TEXT,
                        file_path TEXT,
                        project_id TEXT,
                        user_id TEXT,
                        organization_id TEXT,
                        detection_method TEXT,
                        confidence_score REAL,
                        false_positive BOOLEAN DEFAULT FALSE,
                        resolved BOOLEAN DEFAULT FALSE,
                        resolution_time INTEGER,
                        metadata TEXT
                    )
                ''')
                
                # Scan events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        scan_id TEXT NOT NULL,
                        project_id TEXT,
                        user_id TEXT,
                        organization_id TEXT,
                        scan_type TEXT,
                        files_scanned INTEGER,
                        vulnerabilities_found INTEGER,
                        scan_duration REAL,
                        lines_of_code INTEGER,
                        languages TEXT,
                        success BOOLEAN DEFAULT TRUE,
                        error_message TEXT
                    )
                ''')
                
                # User activity table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_activity (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        user_id TEXT NOT NULL,
                        organization_id TEXT,
                        activity_type TEXT NOT NULL,
                        resource_type TEXT,
                        resource_id TEXT,
                        action TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        success BOOLEAN DEFAULT TRUE,
                        metadata TEXT
                    )
                ''')
                
                # Performance metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        service_name TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        unit TEXT,
                        tags TEXT
                    )
                ''')
                
                # Compliance events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        regulation TEXT NOT NULL,
                        violation_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        project_id TEXT,
                        organization_id TEXT,
                        file_path TEXT,
                        description TEXT,
                        remediation_status TEXT DEFAULT 'open',
                        remediation_time INTEGER
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_timestamp ON vulnerability_events(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_org ON vulnerability_events(organization_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_events(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_org ON scan_events(organization_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON user_activity(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_user ON user_activity(user_id)')
                
                conn.commit()
                logging.info("Analytics database initialized successfully")
                
        except Exception as e:
            logging.error(f"Failed to initialize analytics database: {e}")
    
    def record_vulnerability_event(self, event_data: Dict[str, Any]):
        """Record a vulnerability detection event"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO vulnerability_events 
                    (vulnerability_id, vulnerability_type, severity, language, file_path, 
                     project_id, user_id, organization_id, detection_method, confidence_score, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_data.get('vulnerability_id'),
                    event_data.get('vulnerability_type'),
                    event_data.get('severity'),
                    event_data.get('language'),
                    event_data.get('file_path'),
                    event_data.get('project_id'),
                    event_data.get('user_id'),
                    event_data.get('organization_id'),
                    event_data.get('detection_method'),
                    event_data.get('confidence_score'),
                    json.dumps(event_data.get('metadata', {}))
                ))
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to record vulnerability event: {e}")
    
    def record_scan_event(self, event_data: Dict[str, Any]):
        """Record a scan event"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_events 
                    (scan_id, project_id, user_id, organization_id, scan_type, 
                     files_scanned, vulnerabilities_found, scan_duration, lines_of_code, languages, success)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_data.get('scan_id'),
                    event_data.get('project_id'),
                    event_data.get('user_id'),
                    event_data.get('organization_id'),
                    event_data.get('scan_type'),
                    event_data.get('files_scanned'),
                    event_data.get('vulnerabilities_found'),
                    event_data.get('scan_duration'),
                    event_data.get('lines_of_code'),
                    json.dumps(event_data.get('languages', [])),
                    event_data.get('success', True)
                ))
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to record scan event: {e}")
    
    def record_user_activity(self, event_data: Dict[str, Any]):
        """Record user activity event"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_activity 
                    (user_id, organization_id, activity_type, resource_type, resource_id, 
                     action, ip_address, user_agent, success, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_data.get('user_id'),
                    event_data.get('organization_id'),
                    event_data.get('activity_type'),
                    event_data.get('resource_type'),
                    event_data.get('resource_id'),
                    event_data.get('action'),
                    event_data.get('ip_address'),
                    event_data.get('user_agent'),
                    event_data.get('success', True),
                    json.dumps(event_data.get('metadata', {}))
                ))
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to record user activity: {e}")
    
    def get_security_dashboard_data(self, organization_id: str = None, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Build WHERE clause for organization filtering
                org_filter = ""
                params = [start_date.isoformat(), end_date.isoformat()]
                if organization_id:
                    org_filter = "AND organization_id = ?"
                    params.append(organization_id)
                
                # Get vulnerability metrics
                vulnerability_metrics = self._get_vulnerability_metrics(conn, org_filter, params)
                
                # Get scan metrics
                scan_metrics = self._get_scan_metrics(conn, org_filter, params)
                
                # Get compliance metrics
                compliance_metrics = self._get_compliance_metrics(conn, org_filter, params)
                
                # Get trend data
                trend_data = self._get_trend_data(conn, org_filter, params, days)
                
                # Get top vulnerabilities
                top_vulnerabilities = self._get_top_vulnerabilities(conn, org_filter, params)
                
                # Get language distribution
                language_distribution = self._get_language_distribution(conn, org_filter, params)
                
                # Get user activity summary
                user_activity = self._get_user_activity_summary(conn, org_filter, params)
                
                return {
                    'period': {
                        'start_date': start_date.isoformat(),
                        'end_date': end_date.isoformat(),
                        'days': days
                    },
                    'vulnerability_metrics': vulnerability_metrics,
                    'scan_metrics': scan_metrics,
                    'compliance_metrics': compliance_metrics,
                    'trends': trend_data,
                    'top_vulnerabilities': top_vulnerabilities,
                    'language_distribution': language_distribution,
                    'user_activity': user_activity,
                    'generated_at': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logging.error(f"Failed to get dashboard data: {e}")
            return {}
    
    def _get_vulnerability_metrics(self, conn, org_filter: str, params: List) -> Dict[str, Any]:
        """Get vulnerability-related metrics"""
        cursor = conn.cursor()
        
        # Total vulnerabilities
        cursor.execute(f'''
            SELECT COUNT(*) FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
        ''', params)
        total_vulnerabilities = cursor.fetchone()[0]
        
        # Vulnerabilities by severity
        cursor.execute(f'''
            SELECT severity, COUNT(*) FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY severity
        ''', params)
        severity_counts = dict(cursor.fetchall())
        
        # False positive rate
        cursor.execute(f'''
            SELECT 
                COUNT(CASE WHEN false_positive = 1 THEN 1 END) * 100.0 / COUNT(*) as fp_rate
            FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
        ''', params)
        false_positive_rate = cursor.fetchone()[0] or 0
        
        # Resolution metrics
        cursor.execute(f'''
            SELECT 
                COUNT(CASE WHEN resolved = 1 THEN 1 END) as resolved,
                AVG(CASE WHEN resolved = 1 THEN resolution_time END) as avg_resolution_time
            FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
        ''', params)
        resolution_data = cursor.fetchone()
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'severity_distribution': severity_counts,
            'false_positive_rate': round(false_positive_rate, 2),
            'resolved_count': resolution_data[0] or 0,
            'average_resolution_time_hours': round((resolution_data[1] or 0) / 3600, 2)
        }
    
    def _get_scan_metrics(self, conn, org_filter: str, params: List) -> Dict[str, Any]:
        """Get scan-related metrics"""
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute(f'''
            SELECT COUNT(*) FROM scan_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
        ''', params)
        total_scans = cursor.fetchone()[0]
        
        # Scan success rate
        cursor.execute(f'''
            SELECT 
                COUNT(CASE WHEN success = 1 THEN 1 END) * 100.0 / COUNT(*) as success_rate
            FROM scan_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
        ''', params)
        success_rate = cursor.fetchone()[0] or 0
        
        # Average scan metrics
        cursor.execute(f'''
            SELECT 
                AVG(scan_duration) as avg_duration,
                AVG(files_scanned) as avg_files,
                AVG(vulnerabilities_found) as avg_vulns,
                SUM(lines_of_code) as total_loc
            FROM scan_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter} AND success = 1
        ''', params)
        avg_metrics = cursor.fetchone()
        
        return {
            'total_scans': total_scans,
            'success_rate': round(success_rate, 2),
            'average_duration_seconds': round(avg_metrics[0] or 0, 2),
            'average_files_scanned': round(avg_metrics[1] or 0, 0),
            'average_vulnerabilities_found': round(avg_metrics[2] or 0, 1),
            'total_lines_of_code': int(avg_metrics[3] or 0)
        }
    
    def _get_compliance_metrics(self, conn, org_filter: str, params: List) -> Dict[str, Any]:
        """Get compliance-related metrics"""
        cursor = conn.cursor()
        
        # Compliance violations by regulation
        cursor.execute(f'''
            SELECT regulation, COUNT(*) FROM compliance_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY regulation
        ''', params)
        regulation_violations = dict(cursor.fetchall())
        
        # Compliance violations by severity
        cursor.execute(f'''
            SELECT severity, COUNT(*) FROM compliance_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY severity
        ''', params)
        severity_violations = dict(cursor.fetchall())
        
        # Remediation status
        cursor.execute(f'''
            SELECT remediation_status, COUNT(*) FROM compliance_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY remediation_status
        ''', params)
        remediation_status = dict(cursor.fetchall())
        
        return {
            'violations_by_regulation': regulation_violations,
            'violations_by_severity': severity_violations,
            'remediation_status': remediation_status
        }
    
    def _get_trend_data(self, conn, org_filter: str, params: List, days: int) -> Dict[str, Any]:
        """Get trend data for charts"""
        cursor = conn.cursor()
        
        # Daily vulnerability trends
        cursor.execute(f'''
            SELECT 
                DATE(timestamp) as date,
                severity,
                COUNT(*) as count
            FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY DATE(timestamp), severity
            ORDER BY date
        ''', params)
        
        daily_trends = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
        for row in cursor.fetchall():
            date, severity, count = row
            daily_trends[date][severity] = count
        
        # Convert to list format for charts
        trend_list = []
        for date in sorted(daily_trends.keys()):
            trend_list.append({
                'date': date,
                'critical': daily_trends[date]['CRITICAL'],
                'high': daily_trends[date]['HIGH'],
                'medium': daily_trends[date]['MEDIUM'],
                'low': daily_trends[date]['LOW'],
                'total': sum(daily_trends[date].values())
            })
        
        return {
            'daily_vulnerabilities': trend_list
        }
    
    def _get_top_vulnerabilities(self, conn, org_filter: str, params: List) -> List[Dict[str, Any]]:
        """Get top vulnerability types"""
        cursor = conn.cursor()
        
        cursor.execute(f'''
            SELECT 
                vulnerability_type,
                COUNT(*) as count,
                AVG(confidence_score) as avg_confidence
            FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY vulnerability_type
            ORDER BY count DESC
            LIMIT 10
        ''', params)
        
        return [
            {
                'type': row[0],
                'count': row[1],
                'average_confidence': round(row[2] or 0, 2)
            }
            for row in cursor.fetchall()
        ]
    
    def _get_language_distribution(self, conn, org_filter: str, params: List) -> Dict[str, int]:
        """Get programming language distribution"""
        cursor = conn.cursor()
        
        cursor.execute(f'''
            SELECT language, COUNT(*) FROM vulnerability_events 
            WHERE timestamp BETWEEN ? AND ? {org_filter} AND language IS NOT NULL
            GROUP BY language
            ORDER BY COUNT(*) DESC
        ''', params)
        
        return dict(cursor.fetchall())
    
    def _get_user_activity_summary(self, conn, org_filter: str, params: List) -> Dict[str, Any]:
        """Get user activity summary"""
        cursor = conn.cursor()
        
        # Active users
        cursor.execute(f'''
            SELECT COUNT(DISTINCT user_id) FROM user_activity 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
        ''', params)
        active_users = cursor.fetchone()[0]
        
        # Top activities
        cursor.execute(f'''
            SELECT activity_type, COUNT(*) FROM user_activity 
            WHERE timestamp BETWEEN ? AND ? {org_filter}
            GROUP BY activity_type
            ORDER BY COUNT(*) DESC
            LIMIT 5
        ''', params)
        top_activities = dict(cursor.fetchall())
        
        return {
            'active_users': active_users,
            'top_activities': top_activities
        }
    
    def generate_security_report(self, organization_id: str = None, days: int = 30, format: str = 'json') -> Dict[str, Any]:
        """Generate comprehensive security report"""
        dashboard_data = self.get_security_dashboard_data(organization_id, days)
        
        if format == 'json':
            return {
                'report_type': 'security_summary',
                'organization_id': organization_id,
                'period': dashboard_data.get('period', {}),
                'executive_summary': self._generate_executive_summary(dashboard_data),
                'detailed_metrics': dashboard_data,
                'recommendations': self._generate_recommendations(dashboard_data),
                'generated_at': datetime.utcnow().isoformat()
            }
        
        # Additional formats (PDF, Excel) could be implemented here
        return dashboard_data
    
    def _generate_executive_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from dashboard data"""
        vuln_metrics = data.get('vulnerability_metrics', {})
        scan_metrics = data.get('scan_metrics', {})
        
        total_vulns = vuln_metrics.get('total_vulnerabilities', 0)
        critical_vulns = vuln_metrics.get('severity_distribution', {}).get('CRITICAL', 0)
        high_vulns = vuln_metrics.get('severity_distribution', {}).get('HIGH', 0)
        
        risk_level = 'LOW'
        if critical_vulns > 10 or high_vulns > 50:
            risk_level = 'HIGH'
        elif critical_vulns > 5 or high_vulns > 20:
            risk_level = 'MEDIUM'
        
        return {
            'total_vulnerabilities_found': total_vulns,
            'critical_vulnerabilities': critical_vulns,
            'high_severity_vulnerabilities': high_vulns,
            'overall_risk_level': risk_level,
            'scans_performed': scan_metrics.get('total_scans', 0),
            'scan_success_rate': scan_metrics.get('success_rate', 0),
            'false_positive_rate': vuln_metrics.get('false_positive_rate', 0)
        }
    
    def _generate_recommendations(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on data"""
        recommendations = []
        
        vuln_metrics = data.get('vulnerability_metrics', {})
        scan_metrics = data.get('scan_metrics', {})
        top_vulns = data.get('top_vulnerabilities', [])
        
        # High false positive rate
        if vuln_metrics.get('false_positive_rate', 0) > 15:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Detection Accuracy',
                'title': 'Reduce False Positive Rate',
                'description': 'False positive rate is above 15%. Consider tuning detection rules or implementing ML-based filtering.',
                'action_items': [
                    'Review and tune vulnerability detection patterns',
                    'Implement adaptive learning to reduce false positives',
                    'Train team on proper vulnerability classification'
                ]
            })
        
        # Critical vulnerabilities
        critical_count = vuln_metrics.get('severity_distribution', {}).get('CRITICAL', 0)
        if critical_count > 10:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Vulnerability Management',
                'title': 'Address Critical Vulnerabilities',
                'description': f'{critical_count} critical vulnerabilities detected. Immediate action required.',
                'action_items': [
                    'Prioritize remediation of critical vulnerabilities',
                    'Implement emergency patching procedures',
                    'Review code review processes'
                ]
            })
        
        # Low scan success rate
        if scan_metrics.get('success_rate', 100) < 90:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Scan Reliability',
                'title': 'Improve Scan Success Rate',
                'description': 'Scan success rate is below 90%. Investigate and resolve scan failures.',
                'action_items': [
                    'Analyze scan failure logs',
                    'Optimize scan configurations',
                    'Improve error handling in scanning pipeline'
                ]
            })
        
        # Top vulnerability types
        if top_vulns:
            top_vuln_type = top_vulns[0]['type']
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Training',
                'title': f'Focus on {top_vuln_type} Prevention',
                'description': f'{top_vuln_type} is the most common vulnerability type. Targeted training recommended.',
                'action_items': [
                    f'Provide developer training on {top_vuln_type} prevention',
                    'Update coding standards and guidelines',
                    'Implement pre-commit hooks for early detection'
                ]
            })
        
        return recommendations
    
    def get_vulnerability_trends_chart(self, organization_id: str = None, days: int = 30) -> str:
        """Generate vulnerability trends chart"""
        dashboard_data = self.get_security_dashboard_data(organization_id, days)
        trend_data = dashboard_data.get('trends', {}).get('daily_vulnerabilities', [])
        
        if not trend_data:
            return ""
        
        dates = [item['date'] for item in trend_data]
        critical = [item['critical'] for item in trend_data]
        high = [item['high'] for item in trend_data]
        medium = [item['medium'] for item in trend_data]
        low = [item['low'] for item in trend_data]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(x=dates, y=critical, mode='lines+markers', name='Critical', line=dict(color='red')))
        fig.add_trace(go.Scatter(x=dates, y=high, mode='lines+markers', name='High', line=dict(color='orange')))
        fig.add_trace(go.Scatter(x=dates, y=medium, mode='lines+markers', name='Medium', line=dict(color='yellow')))
        fig.add_trace(go.Scatter(x=dates, y=low, mode='lines+markers', name='Low', line=dict(color='green')))
        
        fig.update_layout(
            title='Vulnerability Trends Over Time',
            xaxis_title='Date',
            yaxis_title='Number of Vulnerabilities',
            hovermode='x unified'
        )
        
        return json.dumps(fig, cls=PlotlyJSONEncoder)

# Initialize analytics service
analytics_service = AdvancedAnalyticsService()

@analytics_bp.route('/dashboard', methods=['GET'])
def get_dashboard():
    """Get security dashboard data"""
    organization_id = request.args.get('organization_id')
    days = int(request.args.get('days', 30))
    
    dashboard_data = analytics_service.get_security_dashboard_data(organization_id, days)
    return jsonify(dashboard_data)

@analytics_bp.route('/report', methods=['GET'])
def generate_report():
    """Generate security report"""
    organization_id = request.args.get('organization_id')
    days = int(request.args.get('days', 30))
    format_type = request.args.get('format', 'json')
    
    report = analytics_service.generate_security_report(organization_id, days, format_type)
    return jsonify(report)

@analytics_bp.route('/charts/vulnerability-trends', methods=['GET'])
def get_vulnerability_trends_chart():
    """Get vulnerability trends chart"""
    organization_id = request.args.get('organization_id')
    days = int(request.args.get('days', 30))
    
    chart_json = analytics_service.get_vulnerability_trends_chart(organization_id, days)
    return jsonify({'chart': chart_json})

@analytics_bp.route('/events/vulnerability', methods=['POST'])
def record_vulnerability_event():
    """Record a vulnerability event"""
    event_data = request.get_json()
    analytics_service.record_vulnerability_event(event_data)
    return jsonify({'status': 'recorded'})

@analytics_bp.route('/events/scan', methods=['POST'])
def record_scan_event():
    """Record a scan event"""
    event_data = request.get_json()
    analytics_service.record_scan_event(event_data)
    return jsonify({'status': 'recorded'})

@analytics_bp.route('/events/activity', methods=['POST'])
def record_activity_event():
    """Record a user activity event"""
    event_data = request.get_json()
    analytics_service.record_user_activity(event_data)
    return jsonify({'status': 'recorded'})

# Export the analytics service
__all__ = ['analytics_bp', 'analytics_service']

