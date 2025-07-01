"""
Integrated Security Training for AI Guardian
AI-powered security training recommendations and learning paths
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import os
import hashlib
from collections import defaultdict, Counter

class SkillLevel(Enum):
    """Skill levels for training assessment"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class TrainingType(Enum):
    """Types of security training"""
    INTERACTIVE = "interactive"
    VIDEO = "video"
    DOCUMENTATION = "documentation"
    HANDS_ON = "hands_on"
    ASSESSMENT = "assessment"
    SIMULATION = "simulation"

class LearningObjective(Enum):
    """Learning objectives for training"""
    AWARENESS = "awareness"
    PREVENTION = "prevention"
    DETECTION = "detection"
    RESPONSE = "response"
    REMEDIATION = "remediation"
    ASSESSMENT = "assessment"

@dataclass
class TrainingModule:
    """Individual training module"""
    module_id: str
    title: str
    description: str
    vulnerability_types: List[str]
    skill_level: SkillLevel
    training_type: TrainingType
    duration_minutes: int
    learning_objectives: List[LearningObjective]
    prerequisites: List[str]
    content_url: Optional[str]
    interactive_elements: List[str]
    assessment_criteria: List[str]
    tags: List[str]

@dataclass
class LearningPath:
    """Structured learning path for specific security topics"""
    path_id: str
    name: str
    description: str
    target_audience: List[str]
    estimated_duration_hours: int
    modules: List[str]  # Module IDs in order
    completion_criteria: List[str]
    certification_available: bool
    difficulty_level: SkillLevel

@dataclass
class UserProgress:
    """User's training progress"""
    user_id: str
    module_id: str
    started_at: datetime
    completed_at: Optional[datetime]
    progress_percentage: float
    assessment_score: Optional[float]
    time_spent_minutes: int
    attempts: int
    last_accessed: datetime

@dataclass
class TrainingRecommendation:
    """Training recommendation for a user"""
    recommendation_id: str
    user_id: str
    vulnerability_context: Dict[str, Any]
    recommended_modules: List[str]
    learning_path: Optional[str]
    priority: str
    reasoning: str
    estimated_time: int
    created_at: datetime
    due_date: Optional[datetime]

class SecurityTrainingEngine:
    """AI-powered security training and learning system"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
        self.training_modules = self._initialize_training_modules()
        self.learning_paths = self._initialize_learning_paths()
        self.vulnerability_training_map = self._create_vulnerability_training_map()
        
        # Initialize database tables
        self._initialize_training_tables()
    
    def _initialize_training_modules(self) -> Dict[str, TrainingModule]:
        """Initialize comprehensive training modules"""
        modules = {
            'sql_injection_basics': TrainingModule(
                module_id='sql_injection_basics',
                title='SQL Injection Prevention Fundamentals',
                description='Learn the basics of SQL injection vulnerabilities and how to prevent them',
                vulnerability_types=['sql_injection'],
                skill_level=SkillLevel.BEGINNER,
                training_type=TrainingType.INTERACTIVE,
                duration_minutes=45,
                learning_objectives=[LearningObjective.AWARENESS, LearningObjective.PREVENTION],
                prerequisites=[],
                content_url='https://training.aiguardian.com/sql-injection-basics',
                interactive_elements=['code_examples', 'quiz', 'hands_on_exercise'],
                assessment_criteria=['identify_sql_injection', 'implement_parameterized_queries'],
                tags=['sql', 'injection', 'database', 'security', 'owasp']
            ),
            'sql_injection_advanced': TrainingModule(
                module_id='sql_injection_advanced',
                title='Advanced SQL Injection Defense',
                description='Advanced techniques for preventing and detecting SQL injection attacks',
                vulnerability_types=['sql_injection'],
                skill_level=SkillLevel.ADVANCED,
                training_type=TrainingType.HANDS_ON,
                duration_minutes=90,
                learning_objectives=[LearningObjective.DETECTION, LearningObjective.RESPONSE],
                prerequisites=['sql_injection_basics'],
                content_url='https://training.aiguardian.com/sql-injection-advanced',
                interactive_elements=['lab_environment', 'attack_simulation', 'defense_implementation'],
                assessment_criteria=['detect_advanced_attacks', 'implement_waf_rules', 'incident_response'],
                tags=['sql', 'injection', 'advanced', 'detection', 'waf']
            ),
            'xss_prevention': TrainingModule(
                module_id='xss_prevention',
                title='Cross-Site Scripting (XSS) Prevention',
                description='Comprehensive guide to preventing XSS vulnerabilities',
                vulnerability_types=['xss', 'cross_site_scripting'],
                skill_level=SkillLevel.INTERMEDIATE,
                training_type=TrainingType.INTERACTIVE,
                duration_minutes=60,
                learning_objectives=[LearningObjective.AWARENESS, LearningObjective.PREVENTION],
                prerequisites=[],
                content_url='https://training.aiguardian.com/xss-prevention',
                interactive_elements=['code_review', 'sanitization_examples', 'csp_configuration'],
                assessment_criteria=['identify_xss_vectors', 'implement_output_encoding', 'configure_csp'],
                tags=['xss', 'javascript', 'web_security', 'sanitization']
            ),
            'authentication_security': TrainingModule(
                module_id='authentication_security',
                title='Secure Authentication Implementation',
                description='Best practices for implementing secure authentication systems',
                vulnerability_types=['authentication_bypass', 'weak_authentication'],
                skill_level=SkillLevel.INTERMEDIATE,
                training_type=TrainingType.VIDEO,
                duration_minutes=75,
                learning_objectives=[LearningObjective.PREVENTION, LearningObjective.REMEDIATION],
                prerequisites=[],
                content_url='https://training.aiguardian.com/authentication-security',
                interactive_elements=['implementation_examples', 'security_checklist', 'testing_tools'],
                assessment_criteria=['implement_mfa', 'secure_password_storage', 'session_management'],
                tags=['authentication', 'mfa', 'passwords', 'sessions']
            ),
            'privilege_escalation_defense': TrainingModule(
                module_id='privilege_escalation_defense',
                title='Privilege Escalation Prevention',
                description='Understanding and preventing privilege escalation attacks',
                vulnerability_types=['privilege_escalation'],
                skill_level=SkillLevel.ADVANCED,
                training_type=TrainingType.SIMULATION,
                duration_minutes=120,
                learning_objectives=[LearningObjective.DETECTION, LearningObjective.RESPONSE],
                prerequisites=['authentication_security'],
                content_url='https://training.aiguardian.com/privilege-escalation',
                interactive_elements=['attack_simulation', 'monitoring_setup', 'response_procedures'],
                assessment_criteria=['implement_least_privilege', 'monitor_privilege_changes', 'incident_response'],
                tags=['privilege_escalation', 'access_control', 'monitoring']
            ),
            'code_injection_prevention': TrainingModule(
                module_id='code_injection_prevention',
                title='Code Injection Attack Prevention',
                description='Preventing various forms of code injection attacks',
                vulnerability_types=['code_injection', 'command_injection'],
                skill_level=SkillLevel.INTERMEDIATE,
                training_type=TrainingType.HANDS_ON,
                duration_minutes=90,
                learning_objectives=[LearningObjective.PREVENTION, LearningObjective.DETECTION],
                prerequisites=[],
                content_url='https://training.aiguardian.com/code-injection',
                interactive_elements=['vulnerable_code_analysis', 'secure_coding_examples', 'testing_techniques'],
                assessment_criteria=['identify_injection_points', 'implement_input_validation', 'secure_coding'],
                tags=['code_injection', 'input_validation', 'secure_coding']
            ),
            'secure_coding_fundamentals': TrainingModule(
                module_id='secure_coding_fundamentals',
                title='Secure Coding Fundamentals',
                description='Essential secure coding practices for developers',
                vulnerability_types=['general'],
                skill_level=SkillLevel.BEGINNER,
                training_type=TrainingType.INTERACTIVE,
                duration_minutes=120,
                learning_objectives=[LearningObjective.AWARENESS, LearningObjective.PREVENTION],
                prerequisites=[],
                content_url='https://training.aiguardian.com/secure-coding-fundamentals',
                interactive_elements=['coding_exercises', 'best_practices_guide', 'security_checklist'],
                assessment_criteria=['apply_secure_coding_principles', 'code_review_skills', 'security_testing'],
                tags=['secure_coding', 'fundamentals', 'best_practices']
            ),
            'owasp_top10_overview': TrainingModule(
                module_id='owasp_top10_overview',
                title='OWASP Top 10 Security Risks',
                description='Comprehensive overview of the OWASP Top 10 security risks',
                vulnerability_types=['general'],
                skill_level=SkillLevel.BEGINNER,
                training_type=TrainingType.VIDEO,
                duration_minutes=90,
                learning_objectives=[LearningObjective.AWARENESS],
                prerequisites=[],
                content_url='https://training.aiguardian.com/owasp-top10',
                interactive_elements=['risk_assessment', 'case_studies', 'prevention_strategies'],
                assessment_criteria=['identify_owasp_risks', 'assess_application_security', 'prioritize_fixes'],
                tags=['owasp', 'top10', 'overview', 'risk_assessment']
            ),
            'incident_response_basics': TrainingModule(
                module_id='incident_response_basics',
                title='Security Incident Response Basics',
                description='Fundamentals of security incident response and management',
                vulnerability_types=['general'],
                skill_level=SkillLevel.INTERMEDIATE,
                training_type=TrainingType.SIMULATION,
                duration_minutes=180,
                learning_objectives=[LearningObjective.RESPONSE],
                prerequisites=[],
                content_url='https://training.aiguardian.com/incident-response',
                interactive_elements=['incident_simulation', 'response_procedures', 'communication_templates'],
                assessment_criteria=['execute_response_plan', 'coordinate_response_team', 'document_incidents'],
                tags=['incident_response', 'security_operations', 'procedures']
            ),
            'security_testing_methods': TrainingModule(
                module_id='security_testing_methods',
                title='Security Testing Methodologies',
                description='Various methods and tools for security testing',
                vulnerability_types=['general'],
                skill_level=SkillLevel.INTERMEDIATE,
                training_type=TrainingType.HANDS_ON,
                duration_minutes=150,
                learning_objectives=[LearningObjective.DETECTION, LearningObjective.ASSESSMENT],
                prerequisites=['secure_coding_fundamentals'],
                content_url='https://training.aiguardian.com/security-testing',
                interactive_elements=['tool_demonstrations', 'testing_exercises', 'report_generation'],
                assessment_criteria=['perform_security_tests', 'analyze_results', 'create_reports'],
                tags=['security_testing', 'penetration_testing', 'tools']
            )
        }
        
        return modules
    
    def _initialize_learning_paths(self) -> Dict[str, LearningPath]:
        """Initialize structured learning paths"""
        paths = {
            'developer_security_basics': LearningPath(
                path_id='developer_security_basics',
                name='Developer Security Fundamentals',
                description='Essential security training for software developers',
                target_audience=['developers', 'junior_developers'],
                estimated_duration_hours=8,
                modules=[
                    'secure_coding_fundamentals',
                    'owasp_top10_overview',
                    'sql_injection_basics',
                    'xss_prevention',
                    'authentication_security'
                ],
                completion_criteria=['complete_all_modules', 'pass_final_assessment'],
                certification_available=True,
                difficulty_level=SkillLevel.BEGINNER
            ),
            'advanced_web_security': LearningPath(
                path_id='advanced_web_security',
                name='Advanced Web Application Security',
                description='Advanced security training for web application developers',
                target_audience=['senior_developers', 'security_engineers'],
                estimated_duration_hours=12,
                modules=[
                    'sql_injection_advanced',
                    'code_injection_prevention',
                    'privilege_escalation_defense',
                    'security_testing_methods'
                ],
                completion_criteria=['complete_all_modules', 'pass_practical_assessment', 'complete_capstone_project'],
                certification_available=True,
                difficulty_level=SkillLevel.ADVANCED
            ),
            'security_operations': LearningPath(
                path_id='security_operations',
                name='Security Operations and Incident Response',
                description='Training for security operations and incident response teams',
                target_audience=['security_analysts', 'devops_engineers'],
                estimated_duration_hours=10,
                modules=[
                    'incident_response_basics',
                    'security_testing_methods',
                    'privilege_escalation_defense'
                ],
                completion_criteria=['complete_all_modules', 'pass_simulation_exercises'],
                certification_available=True,
                difficulty_level=SkillLevel.INTERMEDIATE
            ),
            'compliance_security': LearningPath(
                path_id='compliance_security',
                name='Compliance and Regulatory Security',
                description='Security training focused on compliance requirements',
                target_audience=['compliance_officers', 'security_managers'],
                estimated_duration_hours=6,
                modules=[
                    'owasp_top10_overview',
                    'secure_coding_fundamentals',
                    'incident_response_basics'
                ],
                completion_criteria=['complete_all_modules', 'pass_compliance_assessment'],
                certification_available=False,
                difficulty_level=SkillLevel.INTERMEDIATE
            )
        }
        
        return paths
    
    def _create_vulnerability_training_map(self) -> Dict[str, List[str]]:
        """Create mapping from vulnerability types to relevant training modules"""
        mapping = defaultdict(list)
        
        for module_id, module in self.training_modules.items():
            for vuln_type in module.vulnerability_types:
                mapping[vuln_type].append(module_id)
        
        return dict(mapping)
    
    def _initialize_training_tables(self):
        """Initialize database tables for training tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # User progress table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_training_progress (
                    user_id TEXT,
                    module_id TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    progress_percentage REAL,
                    assessment_score REAL,
                    time_spent_minutes INTEGER,
                    attempts INTEGER,
                    last_accessed TEXT,
                    PRIMARY KEY (user_id, module_id)
                )
            """)
            
            # Training recommendations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS training_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    vulnerability_context TEXT,
                    recommended_modules TEXT,
                    learning_path TEXT,
                    priority TEXT,
                    reasoning TEXT,
                    estimated_time INTEGER,
                    created_at TEXT,
                    due_date TEXT,
                    status TEXT DEFAULT 'pending'
                )
            """)
            
            # Training analytics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS training_analytics (
                    user_id TEXT,
                    vulnerability_type TEXT,
                    training_completed BOOLEAN,
                    vulnerability_recurrence INTEGER,
                    improvement_score REAL,
                    last_updated TEXT,
                    PRIMARY KEY (user_id, vulnerability_type)
                )
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error initializing training tables: {e}")
    
    def analyze_user_vulnerabilities(self, user_id: str, time_period_days: int = 30) -> Dict[str, Any]:
        """Analyze user's vulnerability patterns to identify training needs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user's recent vulnerabilities
            cursor.execute("""
                SELECT type, severity, COUNT(*) as count, 
                       MAX(created_at) as latest_occurrence
                FROM scan_results 
                WHERE user_id = ? AND created_at >= date('now', '-{} days')
                GROUP BY type, severity
                ORDER BY count DESC, severity DESC
            """.format(time_period_days), (user_id,))
            
            vulnerability_data = cursor.fetchall()
            
            # Get user's training history
            cursor.execute("""
                SELECT module_id, completed_at, assessment_score
                FROM user_training_progress
                WHERE user_id = ? AND completed_at IS NOT NULL
            """, (user_id,))
            
            training_history = cursor.fetchall()
            conn.close()
            
            # Analyze patterns
            vulnerability_patterns = {}
            for vuln_type, severity, count, latest in vulnerability_data:
                vulnerability_patterns[vuln_type] = {
                    'count': count,
                    'severity': severity,
                    'latest_occurrence': latest,
                    'frequency': count / time_period_days
                }
            
            # Identify training gaps
            completed_modules = set(row[0] for row in training_history)
            training_gaps = self._identify_training_gaps(vulnerability_patterns, completed_modules)
            
            # Calculate skill assessment
            skill_assessment = self._assess_user_skills(vulnerability_patterns, training_history)
            
            return {
                'user_id': user_id,
                'analysis_period_days': time_period_days,
                'vulnerability_patterns': vulnerability_patterns,
                'completed_training_modules': list(completed_modules),
                'training_gaps': training_gaps,
                'skill_assessment': skill_assessment,
                'risk_score': self._calculate_user_risk_score(vulnerability_patterns, completed_modules)
            }
            
        except Exception as e:
            print(f"Error analyzing user vulnerabilities: {e}")
            return {}
    
    def _identify_training_gaps(self, vulnerability_patterns: Dict, completed_modules: set) -> List[Dict]:
        """Identify training gaps based on vulnerability patterns"""
        gaps = []
        
        for vuln_type, pattern in vulnerability_patterns.items():
            # Find relevant training modules
            relevant_modules = self.vulnerability_training_map.get(vuln_type, [])
            
            # Check which modules are not completed
            missing_modules = [module_id for module_id in relevant_modules 
                             if module_id not in completed_modules]
            
            if missing_modules:
                gap = {
                    'vulnerability_type': vuln_type,
                    'occurrence_count': pattern['count'],
                    'severity': pattern['severity'],
                    'missing_modules': missing_modules,
                    'priority': self._calculate_gap_priority(pattern, missing_modules)
                }
                gaps.append(gap)
        
        # Sort by priority
        gaps.sort(key=lambda x: x['priority'], reverse=True)
        return gaps
    
    def _calculate_gap_priority(self, pattern: Dict, missing_modules: List[str]) -> float:
        """Calculate priority score for training gap"""
        # Base priority on frequency and severity
        frequency_score = min(1.0, pattern['frequency'] * 10)  # Normalize frequency
        
        severity_scores = {'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4}
        severity_score = severity_scores.get(pattern['severity'], 0.5)
        
        # Consider number of missing modules
        module_score = len(missing_modules) * 0.1
        
        return frequency_score * 0.5 + severity_score * 0.4 + module_score * 0.1
    
    def _assess_user_skills(self, vulnerability_patterns: Dict, training_history: List) -> Dict[str, Any]:
        """Assess user's current security skills"""
        # Calculate completion rate
        total_relevant_modules = set()
        for vuln_type in vulnerability_patterns.keys():
            relevant_modules = self.vulnerability_training_map.get(vuln_type, [])
            total_relevant_modules.update(relevant_modules)
        
        completed_relevant = len([module for module, _, _ in training_history 
                                if module in total_relevant_modules])
        
        completion_rate = completed_relevant / len(total_relevant_modules) if total_relevant_modules else 0
        
        # Calculate average assessment score
        assessment_scores = [score for _, _, score in training_history if score is not None]
        avg_assessment_score = sum(assessment_scores) / len(assessment_scores) if assessment_scores else 0
        
        # Determine skill level
        if completion_rate >= 0.8 and avg_assessment_score >= 85:
            skill_level = SkillLevel.ADVANCED
        elif completion_rate >= 0.6 and avg_assessment_score >= 75:
            skill_level = SkillLevel.INTERMEDIATE
        elif completion_rate >= 0.3 and avg_assessment_score >= 60:
            skill_level = SkillLevel.BEGINNER
        else:
            skill_level = SkillLevel.BEGINNER
        
        return {
            'completion_rate': completion_rate,
            'average_assessment_score': avg_assessment_score,
            'skill_level': skill_level.value,
            'total_modules_completed': len(training_history),
            'relevant_modules_completed': completed_relevant
        }
    
    def _calculate_user_risk_score(self, vulnerability_patterns: Dict, completed_modules: set) -> float:
        """Calculate user's security risk score"""
        if not vulnerability_patterns:
            return 0.0
        
        # Calculate vulnerability risk
        vuln_risk = 0.0
        for vuln_type, pattern in vulnerability_patterns.items():
            severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            severity_weight = severity_weights.get(pattern['severity'], 1)
            vuln_risk += pattern['count'] * severity_weight * pattern['frequency']
        
        # Calculate training mitigation
        total_relevant_modules = set()
        for vuln_type in vulnerability_patterns.keys():
            relevant_modules = self.vulnerability_training_map.get(vuln_type, [])
            total_relevant_modules.update(relevant_modules)
        
        training_coverage = len(completed_modules & total_relevant_modules) / len(total_relevant_modules) if total_relevant_modules else 0
        training_mitigation = training_coverage * 0.7  # Training can reduce risk by up to 70%
        
        # Final risk score (0-10 scale)
        risk_score = min(10.0, vuln_risk * (1 - training_mitigation))
        return risk_score
    
    def generate_training_recommendations(self, user_id: str, max_recommendations: int = 5) -> List[TrainingRecommendation]:
        """Generate personalized training recommendations"""
        try:
            # Analyze user vulnerabilities
            analysis = self.analyze_user_vulnerabilities(user_id)
            
            if not analysis:
                return []
            
            recommendations = []
            training_gaps = analysis.get('training_gaps', [])
            skill_level = analysis.get('skill_assessment', {}).get('skill_level', 'beginner')
            
            # Generate recommendations based on gaps
            for gap in training_gaps[:max_recommendations]:
                vuln_type = gap['vulnerability_type']
                missing_modules = gap['missing_modules']
                
                # Select most appropriate module based on skill level
                selected_module = self._select_appropriate_module(missing_modules, skill_level)
                
                if selected_module:
                    recommendation = TrainingRecommendation(
                        recommendation_id=hashlib.md5(f"{user_id}{vuln_type}{datetime.now()}".encode()).hexdigest()[:16],
                        user_id=user_id,
                        vulnerability_context={
                            'vulnerability_type': vuln_type,
                            'occurrence_count': gap['occurrence_count'],
                            'severity': gap['severity'],
                            'priority': gap['priority']
                        },
                        recommended_modules=[selected_module],
                        learning_path=self._suggest_learning_path(user_id, skill_level),
                        priority=self._determine_recommendation_priority(gap),
                        reasoning=self._generate_recommendation_reasoning(gap, selected_module),
                        estimated_time=self.training_modules[selected_module].duration_minutes,
                        created_at=datetime.now(),
                        due_date=self._calculate_due_date(gap['priority'])
                    )
                    recommendations.append(recommendation)
            
            # Store recommendations
            for rec in recommendations:
                self._store_recommendation(rec)
            
            return recommendations
            
        except Exception as e:
            print(f"Error generating training recommendations: {e}")
            return []
    
    def _select_appropriate_module(self, module_ids: List[str], skill_level: str) -> Optional[str]:
        """Select the most appropriate module based on skill level"""
        if not module_ids:
            return None
        
        # Filter modules by skill level
        skill_enum = SkillLevel(skill_level)
        appropriate_modules = []
        
        for module_id in module_ids:
            module = self.training_modules.get(module_id)
            if module:
                # Select modules at or slightly above user's skill level
                if (module.skill_level == skill_enum or 
                    (skill_enum == SkillLevel.BEGINNER and module.skill_level == SkillLevel.INTERMEDIATE) or
                    (skill_enum == SkillLevel.INTERMEDIATE and module.skill_level == SkillLevel.ADVANCED)):
                    appropriate_modules.append(module_id)
        
        # If no appropriate modules, select the first available
        return appropriate_modules[0] if appropriate_modules else module_ids[0]
    
    def _suggest_learning_path(self, user_id: str, skill_level: str) -> Optional[str]:
        """Suggest an appropriate learning path"""
        skill_enum = SkillLevel(skill_level)
        
        # Map skill levels to learning paths
        if skill_enum == SkillLevel.BEGINNER:
            return 'developer_security_basics'
        elif skill_enum == SkillLevel.INTERMEDIATE:
            return 'security_operations'
        elif skill_enum == SkillLevel.ADVANCED:
            return 'advanced_web_security'
        
        return None
    
    def _determine_recommendation_priority(self, gap: Dict) -> str:
        """Determine priority level for recommendation"""
        priority_score = gap['priority']
        
        if priority_score >= 0.8:
            return 'high'
        elif priority_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendation_reasoning(self, gap: Dict, module_id: str) -> str:
        """Generate reasoning for the recommendation"""
        vuln_type = gap['vulnerability_type']
        count = gap['occurrence_count']
        severity = gap['severity']
        module = self.training_modules.get(module_id)
        
        reasoning = f"You have encountered {count} {vuln_type} vulnerabilities "
        reasoning += f"with {severity} severity in recent scans. "
        
        if module:
            reasoning += f"The '{module.title}' module will help you understand "
            reasoning += f"and prevent these vulnerabilities through {', '.join(module.learning_objectives)}."
        
        return reasoning
    
    def _calculate_due_date(self, priority: float) -> datetime:
        """Calculate due date based on priority"""
        if priority >= 0.8:
            return datetime.now() + timedelta(days=7)  # High priority: 1 week
        elif priority >= 0.5:
            return datetime.now() + timedelta(days=14)  # Medium priority: 2 weeks
        else:
            return datetime.now() + timedelta(days=30)  # Low priority: 1 month
    
    def _store_recommendation(self, recommendation: TrainingRecommendation):
        """Store training recommendation in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO training_recommendations 
                (recommendation_id, user_id, vulnerability_context, recommended_modules,
                 learning_path, priority, reasoning, estimated_time, created_at, due_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                recommendation.recommendation_id,
                recommendation.user_id,
                json.dumps(recommendation.vulnerability_context),
                json.dumps(recommendation.recommended_modules),
                recommendation.learning_path,
                recommendation.priority,
                recommendation.reasoning,
                recommendation.estimated_time,
                recommendation.created_at.isoformat(),
                recommendation.due_date.isoformat() if recommendation.due_date else None
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error storing recommendation: {e}")
    
    def track_training_progress(self, user_id: str, module_id: str, progress_data: Dict[str, Any]):
        """Track user's training progress"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get existing progress
            cursor.execute("""
                SELECT * FROM user_training_progress 
                WHERE user_id = ? AND module_id = ?
            """, (user_id, module_id))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing progress
                cursor.execute("""
                    UPDATE user_training_progress 
                    SET progress_percentage = ?, assessment_score = ?, 
                        time_spent_minutes = ?, attempts = ?, last_accessed = ?,
                        completed_at = ?
                    WHERE user_id = ? AND module_id = ?
                """, (
                    progress_data.get('progress_percentage', existing[4]),
                    progress_data.get('assessment_score', existing[5]),
                    progress_data.get('time_spent_minutes', existing[6]),
                    progress_data.get('attempts', existing[7]) + 1,
                    datetime.now().isoformat(),
                    progress_data.get('completed_at'),
                    user_id,
                    module_id
                ))
            else:
                # Create new progress record
                cursor.execute("""
                    INSERT INTO user_training_progress 
                    (user_id, module_id, started_at, completed_at, progress_percentage,
                     assessment_score, time_spent_minutes, attempts, last_accessed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    module_id,
                    datetime.now().isoformat(),
                    progress_data.get('completed_at'),
                    progress_data.get('progress_percentage', 0),
                    progress_data.get('assessment_score'),
                    progress_data.get('time_spent_minutes', 0),
                    1,
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            conn.close()
            
            # Update analytics if training completed
            if progress_data.get('completed_at'):
                self._update_training_analytics(user_id, module_id)
            
        except Exception as e:
            print(f"Error tracking training progress: {e}")
    
    def _update_training_analytics(self, user_id: str, module_id: str):
        """Update training analytics after completion"""
        try:
            module = self.training_modules.get(module_id)
            if not module:
                return
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update analytics for each vulnerability type covered by the module
            for vuln_type in module.vulnerability_types:
                cursor.execute("""
                    INSERT OR REPLACE INTO training_analytics 
                    (user_id, vulnerability_type, training_completed, 
                     vulnerability_recurrence, improvement_score, last_updated)
                    VALUES (?, ?, ?, 
                            COALESCE((SELECT vulnerability_recurrence FROM training_analytics 
                                     WHERE user_id = ? AND vulnerability_type = ?), 0),
                            COALESCE((SELECT improvement_score FROM training_analytics 
                                     WHERE user_id = ? AND vulnerability_type = ?), 0) + 10,
                            ?)
                """, (user_id, vuln_type, True, user_id, vuln_type, user_id, vuln_type, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error updating training analytics: {e}")
    
    def get_user_training_dashboard(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive training dashboard for user"""
        try:
            # Get user analysis
            analysis = self.analyze_user_vulnerabilities(user_id)
            
            # Get training progress
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT module_id, progress_percentage, assessment_score, 
                       completed_at, time_spent_minutes
                FROM user_training_progress 
                WHERE user_id = ?
                ORDER BY last_accessed DESC
            """, (user_id,))
            
            progress_data = cursor.fetchall()
            
            # Get recommendations
            cursor.execute("""
                SELECT recommendation_id, priority, reasoning, estimated_time, 
                       due_date, status, recommended_modules
                FROM training_recommendations 
                WHERE user_id = ? AND status = 'pending'
                ORDER BY created_at DESC
            """, (user_id,))
            
            recommendations_data = cursor.fetchall()
            conn.close()
            
            # Process progress data
            completed_modules = [row[0] for row in progress_data if row[3] is not None]
            in_progress_modules = [row[0] for row in progress_data if row[3] is None and row[1] > 0]
            
            # Calculate statistics
            total_time_spent = sum(row[4] for row in progress_data)
            avg_assessment_score = sum(row[2] for row in progress_data if row[2] is not None) / len([row for row in progress_data if row[2] is not None]) if any(row[2] for row in progress_data) else 0
            
            # Process recommendations
            pending_recommendations = []
            for rec_data in recommendations_data:
                rec = {
                    'recommendation_id': rec_data[0],
                    'priority': rec_data[1],
                    'reasoning': rec_data[2],
                    'estimated_time': rec_data[3],
                    'due_date': rec_data[4],
                    'recommended_modules': json.loads(rec_data[6])
                }
                pending_recommendations.append(rec)
            
            dashboard = {
                'user_id': user_id,
                'overview': {
                    'risk_score': analysis.get('risk_score', 0),
                    'skill_level': analysis.get('skill_assessment', {}).get('skill_level', 'beginner'),
                    'completion_rate': analysis.get('skill_assessment', {}).get('completion_rate', 0),
                    'modules_completed': len(completed_modules),
                    'modules_in_progress': len(in_progress_modules),
                    'total_time_spent_hours': total_time_spent / 60,
                    'average_assessment_score': avg_assessment_score
                },
                'vulnerability_analysis': analysis.get('vulnerability_patterns', {}),
                'training_gaps': analysis.get('training_gaps', []),
                'completed_modules': completed_modules,
                'in_progress_modules': in_progress_modules,
                'pending_recommendations': pending_recommendations,
                'suggested_learning_paths': self._get_suggested_learning_paths(analysis),
                'achievements': self._calculate_achievements(user_id, completed_modules, avg_assessment_score),
                'next_steps': self._generate_next_steps(analysis, pending_recommendations)
            }
            
            return dashboard
            
        except Exception as e:
            print(f"Error generating training dashboard: {e}")
            return {}
    
    def _get_suggested_learning_paths(self, analysis: Dict) -> List[Dict]:
        """Get suggested learning paths based on analysis"""
        skill_level = analysis.get('skill_assessment', {}).get('skill_level', 'beginner')
        
        suggested_paths = []
        for path_id, path in self.learning_paths.items():
            if path.difficulty_level.value == skill_level:
                suggested_paths.append({
                    'path_id': path_id,
                    'name': path.name,
                    'description': path.description,
                    'estimated_duration_hours': path.estimated_duration_hours,
                    'certification_available': path.certification_available
                })
        
        return suggested_paths
    
    def _calculate_achievements(self, user_id: str, completed_modules: List[str], avg_score: float) -> List[Dict]:
        """Calculate user achievements"""
        achievements = []
        
        # Module completion achievements
        if len(completed_modules) >= 1:
            achievements.append({
                'title': 'First Steps',
                'description': 'Completed your first security training module',
                'earned_date': datetime.now().isoformat()
            })
        
        if len(completed_modules) >= 5:
            achievements.append({
                'title': 'Security Enthusiast',
                'description': 'Completed 5 security training modules',
                'earned_date': datetime.now().isoformat()
            })
        
        if len(completed_modules) >= 10:
            achievements.append({
                'title': 'Security Expert',
                'description': 'Completed 10 security training modules',
                'earned_date': datetime.now().isoformat()
            })
        
        # Assessment score achievements
        if avg_score >= 90:
            achievements.append({
                'title': 'High Achiever',
                'description': 'Maintained 90%+ average assessment score',
                'earned_date': datetime.now().isoformat()
            })
        
        return achievements
    
    def _generate_next_steps(self, analysis: Dict, recommendations: List[Dict]) -> List[str]:
        """Generate next steps for the user"""
        next_steps = []
        
        if recommendations:
            high_priority_recs = [rec for rec in recommendations if rec['priority'] == 'high']
            if high_priority_recs:
                next_steps.append(f"Complete {len(high_priority_recs)} high-priority training recommendations")
        
        training_gaps = analysis.get('training_gaps', [])
        if training_gaps:
            next_steps.append(f"Address {len(training_gaps)} identified training gaps")
        
        skill_level = analysis.get('skill_assessment', {}).get('skill_level', 'beginner')
        if skill_level == 'beginner':
            next_steps.append("Focus on fundamental security concepts")
        elif skill_level == 'intermediate':
            next_steps.append("Advance to specialized security topics")
        
        next_steps.extend([
            "Regular practice with hands-on exercises",
            "Stay updated with latest security trends",
            "Apply learned concepts in daily work"
        ])
        
        return next_steps[:5]  # Limit to top 5
    
    def generate_team_training_report(self, team_members: List[str]) -> Dict[str, Any]:
        """Generate training report for a team"""
        try:
            team_data = {}
            overall_stats = {
                'total_members': len(team_members),
                'members_with_training': 0,
                'average_completion_rate': 0,
                'average_risk_score': 0,
                'common_vulnerabilities': Counter(),
                'training_gaps': Counter()
            }
            
            for user_id in team_members:
                analysis = self.analyze_user_vulnerabilities(user_id)
                if analysis:
                    team_data[user_id] = analysis
                    overall_stats['members_with_training'] += 1
                    overall_stats['average_completion_rate'] += analysis.get('skill_assessment', {}).get('completion_rate', 0)
                    overall_stats['average_risk_score'] += analysis.get('risk_score', 0)
                    
                    # Aggregate vulnerability patterns
                    for vuln_type in analysis.get('vulnerability_patterns', {}):
                        overall_stats['common_vulnerabilities'][vuln_type] += 1
                    
                    # Aggregate training gaps
                    for gap in analysis.get('training_gaps', []):
                        overall_stats['training_gaps'][gap['vulnerability_type']] += 1
            
            # Calculate averages
            if overall_stats['members_with_training'] > 0:
                overall_stats['average_completion_rate'] /= overall_stats['members_with_training']
                overall_stats['average_risk_score'] /= overall_stats['members_with_training']
            
            # Generate team recommendations
            team_recommendations = self._generate_team_recommendations(overall_stats)
            
            return {
                'team_size': len(team_members),
                'analysis_date': datetime.now().isoformat(),
                'overall_statistics': overall_stats,
                'individual_analysis': team_data,
                'team_recommendations': team_recommendations,
                'priority_training_areas': [vuln for vuln, count in overall_stats['common_vulnerabilities'].most_common(5)]
            }
            
        except Exception as e:
            print(f"Error generating team training report: {e}")
            return {}
    
    def _generate_team_recommendations(self, stats: Dict) -> List[str]:
        """Generate recommendations for team training"""
        recommendations = []
        
        if stats['average_completion_rate'] < 0.5:
            recommendations.append("Implement mandatory security training program")
        
        if stats['average_risk_score'] > 5:
            recommendations.append("Focus on high-risk vulnerability types")
        
        common_vulns = stats['common_vulnerabilities'].most_common(3)
        if common_vulns:
            recommendations.append(f"Team-wide training on {', '.join([vuln for vuln, _ in common_vulns])}")
        
        recommendations.extend([
            "Regular team security workshops",
            "Peer code review with security focus",
            "Gamification of security training",
            "Monthly security awareness sessions"
        ])
        
        return recommendations[:6]  # Limit to top 6

