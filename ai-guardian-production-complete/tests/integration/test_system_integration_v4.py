"""
AI Guardian Enhanced v4.0.0 System Integration Test Suite
Comprehensive testing of all new services and integrations
"""

import unittest
import requests
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import concurrent.futures
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global test data
user_id = "test_user_123"

class AIGuardianV4IntegrationTests(unittest.TestCase):
    """
    Comprehensive integration tests for AI Guardian Enhanced v4.0.0
    
    Tests all new services:
    - Advanced ML Service
    - Blockchain Security Service
    - IoT/Mobile Security Service
    - Cloud Security Service
    - Integrations Service
    - Communications Service
    """
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.base_urls = {
            "code_scanner": "http://localhost:5001",
            "adaptive_learning": "http://localhost:5002",
            "api_gateway": "http://localhost:8000",
            "advanced_ml": "http://localhost:5004",
            "blockchain_security": "http://localhost:5005",
            "iot_mobile_security": "http://localhost:5006",
            "cloud_security": "http://localhost:5007",
            "integrations": "http://localhost:5008",
            "communications": "http://localhost:5009"
        }
        
        cls.test_data = cls._load_test_data()
        cls.test_results = {}
        
        logger.info("Starting AI Guardian v4.0.0 Integration Tests")
    
    @classmethod
    def _load_test_data(cls) -> Dict[str, Any]:
        """Load test data for integration tests"""
        return {
            "vulnerability_sample": {
                "code": "SELECT * FROM users WHERE id = '" + user_id + "'",
                "language": "sql",
                "file_path": "/app/database.py",
                "line_number": 42
            },
            "blockchain_contract": {
                "contract_code": """
                pragma solidity ^0.8.0;
                contract VulnerableContract {
                    mapping(address => uint) public balances;
                    
                    function withdraw() public {
                        uint amount = balances[msg.sender];
                        require(amount > 0);
                        msg.sender.call.value(amount)("");
                        balances[msg.sender] = 0;
                    }
                }
                """,
                "contract_type": "solidity",
                "network": "ethereum"
            },
            "iot_device": {
                "device_type": "smart_camera",
                "ip_address": "192.168.1.100",
                "firmware_version": "1.2.3",
                "manufacturer": "SecureCam Inc"
            },
            "mobile_app": {
                "app_package": "com.example.secureapp",
                "platform": "android",
                "version": "2.1.0",
                "apk_path": "/tmp/test_app.apk"
            },
            "cloud_environment": {
                "provider": "aws",
                "account_id": "123456789012",
                "regions": ["us-east-1", "us-west-2"]
            }
        }
    
    def test_01_service_health_checks(self):
        """Test that all services are running and healthy"""
        logger.info("Testing service health checks...")
        
        health_results = {}
        
        for service_name, base_url in self.base_urls.items():
            try:
                response = requests.get(f"{base_url}/health", timeout=10)
                health_results[service_name] = {
                    "status": response.status_code,
                    "healthy": response.status_code == 200,
                    "response_time": response.elapsed.total_seconds()
                }
                
                if response.status_code == 200:
                    health_data = response.json()
                    health_results[service_name]["version"] = health_data.get(
                        "version", "unknown"
                    )
                    logger.info(f"✅ {service_name} service is healthy")
                else:
                    logger.error(
                        f"❌ {service_name} service health check failed: "
                        f"{response.status_code}"
                    )
                    
            except Exception as e:
                health_results[service_name] = {
                    "status": "error",
                    "healthy": False,
                    "error": str(e)
                }
                logger.error(f"❌ {service_name} service is unreachable: {e}")
        
        self.test_results["health_checks"] = health_results
        
        # Assert that critical services are healthy
        critical_services = ["code_scanner", "api_gateway"]
        for service in critical_services:
            self.assertTrue(
                health_results.get(service, {}).get("healthy", False),
                f"Critical service {service} is not healthy"
            )
    
    def test_02_advanced_ml_service_integration(self):
        """Test Advanced ML Service integration"""
        logger.info("Testing Advanced ML Service integration...")
        
        ml_service_url = self.base_urls["advanced_ml"]
        
        # Test vulnerability detection with transformer model
        test_payload = {
            "code_sample": self.test_data["vulnerability_sample"]["code"],
            "language": self.test_data["vulnerability_sample"]["language"],
            "model_type": "vulnerability_transformer"
        }
        
        try:
            response = requests.post(
                f"{ml_service_url}/api/v1/ml/analyze-vulnerability",
                json=test_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify response structure
            self.assertIn("vulnerability_detected", result)
            self.assertIn("confidence_score", result)
            self.assertIn("vulnerability_type", result)
            self.assertIn("model_used", result)
            
            logger.info("✅ Advanced ML Service vulnerability detection working")
            
        except Exception as e:
            logger.error(f"❌ Advanced ML Service test failed: {e}")
            self.fail(f"Advanced ML Service integration failed: {e}")
    
    def test_03_blockchain_security_integration(self):
        """Test Blockchain Security Service integration"""
        logger.info("Testing Blockchain Security Service integration...")
        
        blockchain_service_url = self.base_urls["blockchain_security"]
        
        # Test smart contract analysis
        test_payload = {
            "contract_data": self.test_data["blockchain_contract"],
            "analysis_type": "comprehensive"
        }
        
        try:
            response = requests.post(
                f"{blockchain_service_url}/api/v1/blockchain/analyze-contract",
                json=test_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify response structure
            self.assertIn("vulnerabilities_found", result)
            self.assertIn("security_score", result)
            self.assertIn("gas_optimization", result)
            self.assertIn("recommendations", result)
            
            logger.info("✅ Blockchain Security Service working")
            
        except Exception as e:
            logger.error(f"❌ Blockchain Security Service test failed: {e}")
            self.fail(f"Blockchain Security Service integration failed: {e}")
    
    def test_04_iot_mobile_security_integration(self):
        """Test IoT/Mobile Security Service integration"""
        logger.info("Testing IoT/Mobile Security Service integration...")
        
        iot_mobile_service_url = self.base_urls["iot_mobile_security"]
        
        # Test IoT device analysis
        iot_payload = {
            "device_data": self.test_data["iot_device"],
            "scan_type": "comprehensive"
        }
        
        try:
            response = requests.post(
                f"{iot_mobile_service_url}/api/v1/iot/analyze-device",
                json=iot_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify IoT analysis response
            self.assertIn("security_issues", result)
            self.assertIn("firmware_analysis", result)
            self.assertIn("network_security", result)
            
            logger.info("✅ IoT Security analysis working")
            
        except Exception as e:
            logger.error(f"❌ IoT Security Service test failed: {e}")
            self.fail(f"IoT Security Service integration failed: {e}")
        
        # Test Mobile app analysis
        mobile_payload = {
            "app_data": self.test_data["mobile_app"],
            "analysis_depth": "deep"
        }
        
        try:
            response = requests.post(
                f"{iot_mobile_service_url}/api/v1/mobile/analyze-android",
                json=mobile_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify mobile analysis response
            self.assertIn("security_issues", result)
            self.assertIn("privacy_analysis", result)
            self.assertIn("malware_detection", result)
            
            logger.info("✅ Mobile Security analysis working")
            
        except Exception as e:
            logger.error(f"❌ Mobile Security Service test failed: {e}")
            self.fail(f"Mobile Security Service integration failed: {e}")
    
    def test_05_cloud_security_integration(self):
        """Test Cloud Security Service integration"""
        logger.info("Testing Cloud Security Service integration...")
        
        cloud_service_url = self.base_urls["cloud_security"]
        
        # Test AWS environment scan
        test_payload = {
            "cloud_environment": self.test_data["cloud_environment"],
            "scan_config": {
                "depth": "comprehensive",
                "compliance_frameworks": ["cis", "pci_dss"]
            }
        }
        
        try:
            response = requests.post(
                f"{cloud_service_url}/api/v1/cloud/aws/scan-environment",
                json=test_payload,
                timeout=45
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify cloud scan response
            self.assertIn("security_findings", result)
            self.assertIn("compliance_status", result)
            self.assertIn("resource_inventory", result)
            self.assertIn("risk_assessment", result)
            
            logger.info("✅ Cloud Security Service working")
            
        except Exception as e:
            logger.error(f"❌ Cloud Security Service test failed: {e}")
            self.fail(f"Cloud Security Service integration failed: {e}")
    
    def test_06_integrations_service_functionality(self):
        """Test Integrations Service functionality"""
        logger.info("Testing Integrations Service functionality...")
        
        integrations_service_url = self.base_urls["integrations"]
        
        # Test SIEM integration (Splunk)
        splunk_payload = {
            "alert_data": {
                "alert_id": "test-alert-001",
                "title": "Test Security Alert",
                "severity": "high",
                "description": "Test alert for integration testing"
            },
            "splunk_config": {
                "host": "localhost",
                "port": 8088,
                "hec_token": "test-token"
            }
        }
        
        try:
            response = requests.post(
                f"{integrations_service_url}/api/v1/siem/splunk/send-alert",
                json=splunk_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify SIEM integration response
            self.assertIn("success", result)
            
            logger.info("✅ SIEM Integration working")
            
        except Exception as e:
            logger.error(f"❌ SIEM Integration test failed: {e}")
            self.fail(f"SIEM Integration failed: {e}")
        
        # Test DevOps integration (Jenkins)
        jenkins_payload = {
            "pipeline_config": {
                "job_name": "security-scan-pipeline",
                "parameters": {"branch": "main"}
            },
            "jenkins_config": {
                "url": "http://localhost:8080",
                "username": "admin",
                "token": "test-token"
            }
        }
        
        try:
            response = requests.post(
                f"{integrations_service_url}/api/v1/devops/jenkins/trigger-scan",
                json=jenkins_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            logger.info("✅ DevOps Integration working")
            
        except Exception as e:
            logger.error(f"❌ DevOps Integration test failed: {e}")
            self.fail(f"DevOps Integration failed: {e}")
        
        # Test notification integration
        notification_payload = {
            "alert_data": {
                "title": "Test Security Alert",
                "description": "Test alert for notification testing",
                "severity": "high"
            },
            "notification_config": {
                "type": "email",
                "recipient": "test@example.com"
            }
        }
        
        try:
            response = requests.post(
                f"{integrations_service_url}/api/v1/integrations/notify",
                json=notification_payload,
                timeout=15
            )
            self.assertEqual(response.status_code, 200)
            logger.info("✅ Integrations service notification sent")

        except Exception as e:
            logger.error(
                f"❌ Integrations service notification test failed: {e}"
            )
            self.fail(f"Integrations service notification test failed: {e}")
    
    def test_07_communications_service_functionality(self):
        """Test Communications Service functionality"""
        logger.info("Testing Communications Service functionality...")
        
        communications_service_url = self.base_urls["communications"]
        
        # Test Jira integration
        jira_payload = {
            "issue_data": {
                "title": "Test Security Issue",
                "description": "Test issue for integration testing",
                "severity": "high",
                "issue_type": "security_vulnerability"
            },
            "jira_config": {
                "jira_url": "https://test.atlassian.net",
                "username": "test@example.com",
                "api_token": "test-token",
                "project_key": "SEC"
            }
        }
        
        try:
            response = requests.post(
                f"{communications_service_url}/api/v1/ticketing/jira/create-issue",
                json=jira_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Verify Jira integration response
            self.assertIn("success", result)
            
            logger.info("✅ Jira Integration working")
            
        except Exception as e:
            logger.error(f"❌ Jira Integration test failed: {e}")
            self.fail(f"Jira Integration failed: {e}")
        
        # Test Slack integration
        slack_payload = {
            "alert_data": {
                "title": "Test Security Alert",
                "description": "Test alert for Slack integration",
                "severity": "high"
            },
            "slack_config": {
                "webhook_url": "https://hooks.slack.com/test",
                "channel": "#security-alerts"
            }
        }
        
        try:
            response = requests.post(
                f"{communications_service_url}/api/v1/messaging/slack/send-alert",
                json=slack_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            logger.info("✅ Slack Integration working")
            
        except Exception as e:
            logger.error(f"❌ Slack Integration test failed: {e}")
            self.fail(f"Slack Integration failed: {e}")
        
        # Test alert integration
        alert_payload = {
            "alert_data": {
                "title": "Test Security Alert",
                "description": "Test alert for alert testing",
                "severity": "high"
            },
            "alert_config": {
                "type": "email",
                "recipient": "test@example.com"
            }
        }
        
        try:
            response = requests.post(
                f"{communications_service_url}/api/v1/communications/send-alert",
                json=alert_payload,
                timeout=15
            )
            self.assertEqual(response.status_code, 200)
            logger.info("✅ Communications service alert sent")

        except Exception as e:
            logger.error(f"❌ Communications service alert test failed: {e}")
            self.fail(f"Communications service alert test failed: {e}")
    
    def test_08_end_to_end_workflow(self):
        """Test complete end-to-end security workflow"""
        logger.info("Testing end-to-end security workflow...")
        
        # Step 1: Scan code with advanced ML
        code_scan_payload = {
            "code_sample": self.test_data["vulnerability_sample"]["code"],
            "language": self.test_data["vulnerability_sample"]["language"],
            "scan_config": {
                "use_ml_models": True,
                "include_remediation": True
            }
        }
        
        try:
            # Scan code
            response = requests.post(
                f"{self.base_urls['code_scanner']}/api/v1/scan/code",
                json=code_scan_payload,
                timeout=30
            )
            
            self.assertEqual(response.status_code, 200)
            scan_result = response.json()
            
            # Step 2: If vulnerabilities found, create Jira issue
            if scan_result.get("vulnerabilities_found", 0) > 0:
                vulnerability = scan_result["vulnerabilities"][0]
                
                jira_payload = {
                    "issue_data": {
                        "title": f"Security Vulnerability: {vulnerability['type']}",
                        "description": vulnerability["description"],
                        "severity": vulnerability["severity"],
                        "issue_type": "security_vulnerability",
                        "affected_assets": [self.test_data["vulnerability_sample"]["file_path"]]
                    },
                    "jira_config": {
                        "jira_url": "https://test.atlassian.net",
                        "username": "test@example.com",
                        "api_token": "test-token",
                        "project_key": "SEC"
                    }
                }
                
                jira_response = requests.post(
                    f"{self.base_urls['communications']}/api/v1/ticketing/jira/create-issue",
                    json=jira_payload,
                    timeout=30
                )
                
                self.assertEqual(jira_response.status_code, 200)
                
                # Step 3: Send Slack notification
                slack_payload = {
                    "alert_data": {
                        "title": f"New Security Issue Created: {vulnerability['type']}",
                        "description": f"Jira issue created for vulnerability in {self.test_data['vulnerability_sample']['file_path']}",
                        "severity": vulnerability["severity"]
                    },
                    "slack_config": {
                        "webhook_url": "https://hooks.slack.com/test",
                        "channel": "#security-alerts"
                    }
                }
                
                slack_response = requests.post(
                    f"{self.base_urls['communications']}/api/v1/messaging/slack/send-alert",
                    json=slack_payload,
                    timeout=30
                )
                
                self.assertEqual(slack_response.status_code, 200)
                
                # Step 4: Check communication service for alert
                time.sleep(5)  # Allow time for processing
                response = requests.get(
                    f"{self.base_urls['communications']}/api/v1/communications/get-alerts",
                    params={"user_id": "test_user"},
                    timeout=15
                )
                self.assertEqual(response.status_code, 200)
                alerts = response.json()
                self.assertGreater(len(alerts), 0)
                self.assertIn("SQL Injection", alerts[0]["title"])
                logger.info("✅ E2E test communication alert verified")
            
        except Exception as e:
            logger.error(f"❌ End-to-end workflow test failed: {e}")
            self.fail(f"End-to-end workflow failed: {e}")
    
    def test_09_performance_benchmarks(self):
        """Test performance benchmarks for all services"""
        logger.info("Testing performance benchmarks...")
        
        performance_results = {}
        
        # Test concurrent requests to each service
        def test_service_performance(service_name, base_url):
            start_time = time.time()
            successful_requests = 0
            failed_requests = 0
            
            def make_request():
                try:
                    response = requests.get(f"{base_url}/health", timeout=5)
                    return response.status_code == 200
                except:
                    return False
            
            # Make 10 concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                
                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        successful_requests += 1
                    else:
                        failed_requests += 1
            
            end_time = time.time()
            total_time = end_time - start_time
            
            return {
                "total_requests": 10,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "total_time": total_time,
                "requests_per_second": 10 / total_time if total_time > 0 else 0,
                "success_rate": (successful_requests / 10) * 100
            }
        
        for service_name, base_url in self.base_urls.items():
            try:
                performance_results[service_name] = test_service_performance(service_name, base_url)
                logger.info(f"✅ {service_name} performance test completed")
            except Exception as e:
                performance_results[service_name] = {"error": str(e)}
                logger.error(f"❌ {service_name} performance test failed: {e}")
        
        self.test_results["performance"] = performance_results
        
        # Assert minimum performance requirements
        for service_name, results in performance_results.items():
            if "error" not in results:
                self.assertGreaterEqual(
                    results["success_rate"], 90,
                    f"{service_name} success rate below 90%"
                )
    
    def test_10_security_validation(self):
        """Test security validation of all services"""
        logger.info("Testing security validation...")
        
        security_results = {}
        
        for service_name, base_url in self.base_urls.items():
            try:
                # Test for common security headers
                response = requests.get(f"{base_url}/health", timeout=10)
                
                security_headers = {
                    "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
                    "X-Frame-Options": response.headers.get("X-Frame-Options"),
                    "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
                    "Strict-Transport-Security": response.headers.get("Strict-Transport-Security")
                }
                
                # Test for unauthorized access
                try:
                    unauthorized_response = requests.get(f"{base_url}/api/v1/admin/config", timeout=5)
                    unauthorized_access = unauthorized_response.status_code != 401
                except:
                    unauthorized_access = False
                
                security_results[service_name] = {
                    "security_headers": security_headers,
                    "unauthorized_access_blocked": not unauthorized_access,
                    "https_enforced": base_url.startswith("https://")
                }
                
                logger.info(f"✅ {service_name} security validation completed")
                
            except Exception as e:
                security_results[service_name] = {"error": str(e)}
                logger.error(f"❌ {service_name} security validation failed: {e}")
        
        self.test_results["security"] = security_results
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests"""
        logger.info("AI Guardian v4.0.0 Integration Tests completed")
        
        # Generate test report
        cls._generate_test_report()
    
    @classmethod
    def _generate_test_report(cls):
        """Generate comprehensive test report"""
        report = {
            "test_suite": "AI Guardian Enhanced v4.0.0 Integration Tests",
            "execution_timestamp": datetime.utcnow().isoformat(),
            "test_results": cls.test_results,
            "summary": {
                "total_services_tested": len(cls.base_urls),
                "services_healthy": sum(1 for result in cls.test_results.get("health_checks", {}).values() 
                                      if result.get("healthy", False)),
                "performance_passed": sum(1 for result in cls.test_results.get("performance", {}).values() 
                                        if result.get("success_rate", 0) >= 90),
                "security_validated": len(cls.test_results.get("security", {}))
            }
        }
        
        # Save report to file
        with open("/tmp/ai_guardian_v4_integration_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info("Test report saved to /tmp/ai_guardian_v4_integration_test_report.json")

if __name__ == "__main__":
    # Run the integration tests
    unittest.main(verbosity=2)

