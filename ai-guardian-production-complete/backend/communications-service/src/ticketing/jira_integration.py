"""
Jira Integration for AI Guardian Enhanced v4.0.0
Comprehensive integration with Jira for security issue management
"""

import json
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import base64

class JiraIntegration:
    """
    Advanced Jira Integration
    
    Features:
    - Security issue creation and management
    - Custom field mapping
    - Workflow automation
    - Bulk operations
    - Advanced search and filtering
    - Custom dashboards and reports
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Jira configuration
        self.default_config = {
            "api_version": "3",
            "timeout": 30,
            "max_retries": 3
        }
        
        # Issue type mappings
        self.issue_type_mappings = self._load_issue_type_mappings()
        
        # Priority mappings
        self.priority_mappings = self._load_priority_mappings()
        
        # Custom field mappings
        self.custom_field_mappings = self._load_custom_field_mappings()
        
        # Security workflow configurations
        self.workflow_configs = self._load_workflow_configs()
        
        self.logger.info("JiraIntegration initialized successfully")
    
    def _load_issue_type_mappings(self) -> Dict[str, Dict]:
        """Load Jira issue type mappings"""
        return {
            "security_vulnerability": {
                "jira_issue_type": "Bug",
                "jira_issue_type_id": "10004",
                "description": "Security vulnerability found by AI Guardian",
                "default_priority": "High"
            },
            "compliance_violation": {
                "jira_issue_type": "Task",
                "jira_issue_type_id": "10003",
                "description": "Compliance violation detected",
                "default_priority": "Medium"
            },
            "security_incident": {
                "jira_issue_type": "Incident",
                "jira_issue_type_id": "10005",
                "description": "Security incident requiring immediate attention",
                "default_priority": "Critical"
            },
            "security_improvement": {
                "jira_issue_type": "Improvement",
                "jira_issue_type_id": "10002",
                "description": "Security improvement recommendation",
                "default_priority": "Low"
            },
            "threat_intelligence": {
                "jira_issue_type": "Story",
                "jira_issue_type_id": "10001",
                "description": "Threat intelligence indicator",
                "default_priority": "Medium"
            }
        }
    
    def _load_priority_mappings(self) -> Dict[str, Dict]:
        """Load Jira priority mappings"""
        return {
            "critical": {
                "jira_priority": "Highest",
                "jira_priority_id": "1",
                "sla_hours": 4,
                "escalation_required": True
            },
            "high": {
                "jira_priority": "High",
                "jira_priority_id": "2",
                "sla_hours": 24,
                "escalation_required": False
            },
            "medium": {
                "jira_priority": "Medium",
                "jira_priority_id": "3",
                "sla_hours": 72,
                "escalation_required": False
            },
            "low": {
                "jira_priority": "Low",
                "jira_priority_id": "4",
                "sla_hours": 168,
                "escalation_required": False
            }
        }
    
    def _load_custom_field_mappings(self) -> Dict[str, str]:
        """Load custom field mappings for AI Guardian data"""
        return {
            "ai_guardian_id": "customfield_10100",
            "vulnerability_type": "customfield_10101",
            "cvss_score": "customfield_10102",
            "affected_assets": "customfield_10103",
            "remediation_steps": "customfield_10104",
            "compliance_framework": "customfield_10105",
            "threat_level": "customfield_10106",
            "scan_timestamp": "customfield_10107",
            "false_positive": "customfield_10108",
            "business_impact": "customfield_10109"
        }
    
    def _load_workflow_configs(self) -> Dict[str, Dict]:
        """Load security workflow configurations"""
        return {
            "vulnerability_workflow": {
                "initial_status": "Open",
                "statuses": {
                    "open": "Open",
                    "in_progress": "In Progress",
                    "under_review": "Under Review",
                    "resolved": "Resolved",
                    "closed": "Closed",
                    "false_positive": "False Positive"
                },
                "transitions": {
                    "start_work": "Start Progress",
                    "resolve": "Resolve Issue",
                    "close": "Close Issue",
                    "reopen": "Reopen Issue",
                    "mark_false_positive": "Mark as False Positive"
                }
            },
            "incident_workflow": {
                "initial_status": "Open",
                "statuses": {
                    "open": "Open",
                    "investigating": "Investigating",
                    "containment": "Containment",
                    "eradication": "Eradication",
                    "recovery": "Recovery",
                    "resolved": "Resolved"
                },
                "transitions": {
                    "start_investigation": "Start Investigation",
                    "begin_containment": "Begin Containment",
                    "start_eradication": "Start Eradication",
                    "begin_recovery": "Begin Recovery",
                    "resolve": "Resolve Incident"
                }
            }
        }
    
    def configure(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure Jira integration"""
        try:
            # Validate configuration
            validation_result = self._validate_config(config)
            if not validation_result["valid"]:
                return {"error": f"Invalid configuration: {validation_result['errors']}"}
            
            # Test connection
            connection_test = self._test_connection(config)
            if not connection_test["success"]:
                return {"error": f"Connection test failed: {connection_test['error']}"}
            
            # Store configuration (in real implementation, would use secure storage)
            self.config = {**self.default_config, **config}
            
            # Get project information
            project_info = self._get_project_info(config)
            
            return {
                "status": "configured",
                "connection_status": "active",
                "jira_url": config.get("jira_url", ""),
                "project_key": config.get("project_key", ""),
                "project_info": project_info,
                "issue_types_available": list(self.issue_type_mappings.keys()),
                "configuration_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error configuring Jira integration: {e}")
            return {"error": str(e)}
    
    def create_security_issue(self, issue_data: Dict[str, Any], 
                            jira_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create security issue in Jira"""
        try:
            config = jira_config or getattr(self, 'config', self.default_config)
            
            # Determine issue type
            issue_type = issue_data.get("issue_type", "security_vulnerability")
            issue_mapping = self.issue_type_mappings.get(issue_type, self.issue_type_mappings["security_vulnerability"])
            
            # Map priority
            severity = issue_data.get("severity", "medium")
            priority_mapping = self.priority_mappings.get(severity, self.priority_mappings["medium"])
            
            # Build Jira issue payload
            jira_issue = self._build_jira_issue_payload(issue_data, issue_mapping, priority_mapping, config)
            
            # Create issue via Jira API
            result = self._create_issue_via_api(jira_issue, config)
            
            if result["success"]:
                # Add attachments if any
                if issue_data.get("attachments"):
                    attachment_result = self._add_attachments(result["issue_key"], issue_data["attachments"], config)
                    result["attachments"] = attachment_result
                
                # Create sub-tasks if needed
                if issue_data.get("create_subtasks", False):
                    subtask_result = self._create_remediation_subtasks(result["issue_key"], issue_data, config)
                    result["subtasks"] = subtask_result
                
                # Set up watchers
                if issue_data.get("watchers"):
                    watcher_result = self._add_watchers(result["issue_key"], issue_data["watchers"], config)
                    result["watchers"] = watcher_result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error creating Jira security issue: {e}")
            return {"error": str(e)}
    
    def update_security_issue(self, issue_key: str, update_data: Dict[str, Any], 
                            jira_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Update existing security issue in Jira"""
        try:
            config = jira_config or getattr(self, 'config', self.default_config)
            
            # Build update payload
            update_payload = self._build_update_payload(update_data, config)
            
            # Update issue via Jira API
            result = self._update_issue_via_api(issue_key, update_payload, config)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error updating Jira security issue: {e}")
            return {"error": str(e)}
    
    def transition_issue(self, issue_key: str, transition_name: str, 
                        jira_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Transition security issue to different status"""
        try:
            config = jira_config or getattr(self, 'config', self.default_config)
            
            # Get available transitions
            transitions = self._get_available_transitions(issue_key, config)
            
            # Find matching transition
            transition_id = None
            for transition in transitions:
                if transition["name"].lower() == transition_name.lower():
                    transition_id = transition["id"]
                    break
            
            if not transition_id:
                return {"error": f"Transition '{transition_name}' not available for issue {issue_key}"}
            
            # Execute transition
            result = self._execute_transition(issue_key, transition_id, config)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error transitioning Jira issue: {e}")
            return {"error": str(e)}
    
    def search_security_issues(self, search_criteria: Dict[str, Any], 
                             jira_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Search for security issues in Jira"""
        try:
            config = jira_config or getattr(self, 'config', self.default_config)
            
            # Build JQL query
            jql_query = self._build_jql_query(search_criteria, config)
            
            # Execute search
            result = self._execute_search(jql_query, config)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error searching Jira security issues: {e}")
            return {"error": str(e)}
    
    def create_security_dashboard(self, dashboard_config: Dict[str, Any], 
                                jira_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create security dashboard in Jira"""
        try:
            config = jira_config or getattr(self, 'config', self.default_config)
            
            # Build dashboard configuration
            dashboard_data = self._build_dashboard_config(dashboard_config, config)
            
            # Create dashboard via API
            result = self._create_dashboard_via_api(dashboard_data, config)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error creating Jira security dashboard: {e}")
            return {"error": str(e)}
    
    def bulk_create_issues(self, issues_data: List[Dict[str, Any]], 
                          jira_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create multiple security issues in bulk"""
        try:
            config = jira_config or getattr(self, 'config', self.default_config)
            
            results = []
            successful_creates = 0
            failed_creates = 0
            
            for issue_data in issues_data:
                try:
                    result = self.create_security_issue(issue_data, config)
                    if result.get("success", False):
                        successful_creates += 1
                    else:
                        failed_creates += 1
                    results.append(result)
                except Exception as e:
                    failed_creates += 1
                    results.append({"error": str(e)})
            
            return {
                "bulk_create_results": results,
                "total_issues": len(issues_data),
                "successful_creates": successful_creates,
                "failed_creates": failed_creates,
                "success_rate": (successful_creates / len(issues_data)) * 100 if issues_data else 0,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk Jira issue creation: {e}")
            return {"error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get Jira integration status"""
        try:
            config = getattr(self, 'config', None)
            
            if not config:
                return {
                    "status": "not_configured",
                    "connection": "unknown",
                    "last_check": datetime.utcnow().isoformat()
                }
            
            # Test connection
            connection_test = self._test_connection(config)
            
            return {
                "status": "configured",
                "connection": "active" if connection_test["success"] else "failed",
                "jira_url": config.get("jira_url", "unknown"),
                "project_key": config.get("project_key", "unknown"),
                "api_version": config.get("api_version", "3"),
                "issue_types_configured": len(self.issue_type_mappings),
                "custom_fields_mapped": len(self.custom_field_mappings),
                "last_check": datetime.utcnow().isoformat(),
                "connection_error": connection_test.get("error") if not connection_test["success"] else None
            }
            
        except Exception as e:
            self.logger.error(f"Error getting Jira status: {e}")
            return {"error": str(e)}
    
    def test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test connection to Jira"""
        return self._test_connection(config)
    
    def _validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Jira configuration"""
        errors = []
        
        required_fields = ["jira_url", "username", "api_token", "project_key"]
        for field in required_fields:
            if field not in config:
                errors.append(f"Missing required field: {field}")
        
        if "jira_url" in config and not config["jira_url"].startswith(("http://", "https://")):
            errors.append("Jira URL must start with http:// or https://")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def _test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test connection to Jira"""
        try:
            # Mock connection test (in real implementation, would make actual API call)
            jira_url = config.get("jira_url", "")
            
            # Simulate successful connection
            return {
                "success": True,
                "response_time": 200,
                "jira_version": "8.20.0",
                "project_accessible": True,
                "permissions": ["CREATE_ISSUES", "EDIT_ISSUES", "VIEW_ISSUES"]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_project_info(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Get Jira project information"""
        # Mock project information
        return {
            "project_key": config.get("project_key", ""),
            "project_name": "Security Issues",
            "project_type": "software",
            "lead": "security-team",
            "issue_types": ["Bug", "Task", "Story", "Incident"],
            "workflows": ["Security Workflow", "Incident Response Workflow"]
        }
    
    def _build_jira_issue_payload(self, issue_data: Dict[str, Any], 
                                issue_mapping: Dict[str, Any], 
                                priority_mapping: Dict[str, Any], 
                                config: Dict[str, Any]) -> Dict[str, Any]:
        """Build Jira issue creation payload"""
        
        # Basic issue fields
        payload = {
            "fields": {
                "project": {"key": config.get("project_key", "")},
                "issuetype": {"id": issue_mapping["jira_issue_type_id"]},
                "summary": issue_data.get("title", "Security Issue from AI Guardian"),
                "description": self._format_description(issue_data),
                "priority": {"id": priority_mapping["jira_priority_id"]},
                "reporter": {"name": config.get("username", "ai-guardian")}
            }
        }
        
        # Add custom fields
        custom_fields = self._map_custom_fields(issue_data)
        payload["fields"].update(custom_fields)
        
        # Add labels
        labels = issue_data.get("tags", [])
        labels.append("ai-guardian")
        labels.append(f"severity-{issue_data.get('severity', 'medium')}")
        payload["fields"]["labels"] = labels
        
        # Add components if configured
        if config.get("default_component"):
            payload["fields"]["components"] = [{"name": config["default_component"]}]
        
        return payload
    
    def _format_description(self, issue_data: Dict[str, Any]) -> str:
        """Format issue description for Jira"""
        description_parts = []
        
        # Main description
        if issue_data.get("description"):
            description_parts.append(f"*Description:*\n{issue_data['description']}")
        
        # Vulnerability details
        if issue_data.get("vulnerability_type"):
            description_parts.append(f"*Vulnerability Type:* {issue_data['vulnerability_type']}")
        
        if issue_data.get("cvss_score"):
            description_parts.append(f"*CVSS Score:* {issue_data['cvss_score']}")
        
        if issue_data.get("cve_id"):
            description_parts.append(f"*CVE ID:* {issue_data['cve_id']}")
        
        # Affected assets
        if issue_data.get("affected_assets"):
            assets = ", ".join(issue_data["affected_assets"])
            description_parts.append(f"*Affected Assets:* {assets}")
        
        # Remediation steps
        if issue_data.get("remediation"):
            description_parts.append(f"*Remediation:*\n{issue_data['remediation']}")
        
        # AI Guardian metadata
        description_parts.append(f"*Detected by:* AI Guardian v4.0.0")
        description_parts.append(f"*Detection Time:* {issue_data.get('timestamp', datetime.utcnow().isoformat())}")
        
        if issue_data.get("scan_id"):
            description_parts.append(f"*Scan ID:* {issue_data['scan_id']}")
        
        return "\n\n".join(description_parts)
    
    def _map_custom_fields(self, issue_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map AI Guardian data to Jira custom fields"""
        custom_fields = {}
        
        # Map known fields
        field_mappings = {
            "ai_guardian_id": issue_data.get("alert_id", ""),
            "vulnerability_type": issue_data.get("vulnerability_type", ""),
            "cvss_score": issue_data.get("cvss_score", 0),
            "affected_assets": issue_data.get("affected_assets", []),
            "remediation_steps": issue_data.get("remediation", ""),
            "compliance_framework": issue_data.get("compliance_framework", ""),
            "threat_level": issue_data.get("threat_level", ""),
            "scan_timestamp": issue_data.get("timestamp", ""),
            "false_positive": False,
            "business_impact": issue_data.get("business_impact", "")
        }
        
        for field_name, field_value in field_mappings.items():
            if field_value and field_name in self.custom_field_mappings:
                custom_field_id = self.custom_field_mappings[field_name]
                custom_fields[custom_field_id] = field_value
        
        return custom_fields
    
    def _create_issue_via_api(self, issue_payload: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Create issue via Jira REST API"""
        try:
            # Mock issue creation (in real implementation, would make HTTP POST request)
            issue_key = f"{config.get('project_key', 'SEC')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            
            return {
                "success": True,
                "issue_key": issue_key,
                "issue_id": "12345",
                "issue_url": f"{config.get('jira_url', '')}/browse/{issue_key}",
                "creation_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _build_update_payload(self, update_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Build issue update payload"""
        payload = {"fields": {}}
        
        # Map update fields
        if "description" in update_data:
            payload["fields"]["description"] = update_data["description"]
        
        if "priority" in update_data:
            priority_mapping = self.priority_mappings.get(update_data["priority"])
            if priority_mapping:
                payload["fields"]["priority"] = {"id": priority_mapping["jira_priority_id"]}
        
        # Add custom field updates
        custom_updates = self._map_custom_fields(update_data)
        payload["fields"].update(custom_updates)
        
        return payload
    
    def _update_issue_via_api(self, issue_key: str, update_payload: Dict[str, Any], 
                            config: Dict[str, Any]) -> Dict[str, Any]:
        """Update issue via Jira REST API"""
        try:
            # Mock issue update
            return {
                "success": True,
                "issue_key": issue_key,
                "updated_fields": list(update_payload["fields"].keys()),
                "update_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_available_transitions(self, issue_key: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get available transitions for issue"""
        # Mock transitions
        return [
            {"id": "11", "name": "Start Progress"},
            {"id": "21", "name": "Resolve Issue"},
            {"id": "31", "name": "Close Issue"},
            {"id": "41", "name": "Mark as False Positive"}
        ]
    
    def _execute_transition(self, issue_key: str, transition_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute issue transition"""
        try:
            # Mock transition execution
            return {
                "success": True,
                "issue_key": issue_key,
                "transition_id": transition_id,
                "new_status": "In Progress",
                "transition_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _build_jql_query(self, search_criteria: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Build JQL query from search criteria"""
        jql_parts = []
        
        # Project filter
        jql_parts.append(f"project = {config.get('project_key', 'SEC')}")
        
        # Add search criteria
        if search_criteria.get("severity"):
            jql_parts.append(f"labels = severity-{search_criteria['severity']}")
        
        if search_criteria.get("status"):
            jql_parts.append(f"status = '{search_criteria['status']}'")
        
        if search_criteria.get("assignee"):
            jql_parts.append(f"assignee = '{search_criteria['assignee']}'")
        
        if search_criteria.get("created_after"):
            jql_parts.append(f"created >= '{search_criteria['created_after']}'")
        
        # Add AI Guardian filter
        jql_parts.append("labels = ai-guardian")
        
        return " AND ".join(jql_parts)
    
    def _execute_search(self, jql_query: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute JQL search"""
        try:
            # Mock search results
            return {
                "success": True,
                "total_issues": 25,
                "issues": [
                    {
                        "key": "SEC-123",
                        "summary": "SQL Injection vulnerability",
                        "status": "Open",
                        "priority": "High",
                        "assignee": "security-team"
                    },
                    {
                        "key": "SEC-124",
                        "summary": "XSS vulnerability",
                        "status": "In Progress",
                        "priority": "Medium",
                        "assignee": "dev-team"
                    }
                ],
                "jql_query": jql_query,
                "search_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _add_attachments(self, issue_key: str, attachments: List[Dict[str, Any]], 
                        config: Dict[str, Any]) -> Dict[str, Any]:
        """Add attachments to Jira issue"""
        try:
            # Mock attachment addition
            return {
                "success": True,
                "attachments_added": len(attachments),
                "attachment_ids": [f"att_{i}" for i in range(len(attachments))]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _create_remediation_subtasks(self, parent_issue_key: str, issue_data: Dict[str, Any], 
                                   config: Dict[str, Any]) -> Dict[str, Any]:
        """Create remediation subtasks"""
        try:
            # Mock subtask creation
            subtasks = []
            remediation_steps = issue_data.get("remediation_steps", [])
            
            for i, step in enumerate(remediation_steps[:3]):  # Limit to 3 subtasks
                subtask_key = f"{parent_issue_key}-{i+1}"
                subtasks.append({
                    "key": subtask_key,
                    "summary": f"Remediation Step {i+1}: {step[:50]}...",
                    "status": "To Do"
                })
            
            return {
                "success": True,
                "subtasks_created": len(subtasks),
                "subtasks": subtasks
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _add_watchers(self, issue_key: str, watchers: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
        """Add watchers to Jira issue"""
        try:
            # Mock watcher addition
            return {
                "success": True,
                "watchers_added": len(watchers),
                "watchers": watchers
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _build_dashboard_config(self, dashboard_config: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Build dashboard configuration"""
        return {
            "name": dashboard_config.get("name", "AI Guardian Security Dashboard"),
            "description": "Security issues and metrics from AI Guardian",
            "gadgets": [
                {
                    "type": "filter_results",
                    "title": "Open Security Issues",
                    "filter_id": "security_issues_open"
                },
                {
                    "type": "pie_chart",
                    "title": "Issues by Severity",
                    "filter_id": "security_issues_by_severity"
                },
                {
                    "type": "created_vs_resolved",
                    "title": "Created vs Resolved",
                    "filter_id": "security_issues_trend"
                }
            ]
        }
    
    def _create_dashboard_via_api(self, dashboard_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Create dashboard via Jira API"""
        try:
            # Mock dashboard creation
            return {
                "success": True,
                "dashboard_id": "12345",
                "dashboard_name": dashboard_data["name"],
                "dashboard_url": f"{config.get('jira_url', '')}/secure/Dashboard.jspa?selectPageId=12345",
                "creation_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

