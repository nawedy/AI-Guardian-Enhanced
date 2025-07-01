"""
Multi-Tenant Support Service for AI Guardian
Provides organization isolation, tenant management, and resource allocation
"""

from flask import Blueprint, request, jsonify, g
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json
import logging
import os
import uuid
from functools import wraps
from dataclasses import dataclass
from enum import Enum

multi_tenant_bp = Blueprint('multi_tenant', __name__)

Base = declarative_base()

class TenantStatus(Enum):
    """Tenant status enumeration"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"

class SubscriptionTier(Enum):
    """Subscription tier enumeration"""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"

@dataclass
class TenantLimits:
    """Tenant resource limits"""
    max_users: int
    max_projects: int
    max_scans_per_month: int
    max_storage_gb: int
    max_api_calls_per_hour: int
    retention_days: int
    advanced_features: List[str]

class Organization(Base):
    """Organization/Tenant model"""
    __tablename__ = 'organizations'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    domain = Column(String(255))
    status = Column(String(20), default=TenantStatus.ACTIVE.value)
    subscription_tier = Column(String(20), default=SubscriptionTier.FREE.value)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Subscription details
    subscription_start = Column(DateTime)
    subscription_end = Column(DateTime)
    trial_end = Column(DateTime)
    
    # Configuration
    settings = Column(JSON, default=dict)
    limits = Column(JSON, default=dict)
    
    # Relationships
    users = relationship("OrganizationUser", back_populates="organization")
    projects = relationship("Project", back_populates="organization")

class OrganizationUser(Base):
    """Organization user membership"""
    __tablename__ = 'organization_users'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id'), nullable=False)
    user_id = Column(String(255), nullable=False)
    role = Column(String(50), default='member')
    status = Column(String(20), default='active')
    joined_at = Column(DateTime, default=datetime.utcnow)
    last_active = Column(DateTime)
    
    # Permissions
    permissions = Column(JSON, default=list)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")

class Project(Base):
    """Project model"""
    __tablename__ = 'projects'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id'), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    repository_url = Column(String(500))
    status = Column(String(20), default='active')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Project settings
    settings = Column(JSON, default=dict)
    
    # Relationships
    organization = relationship("Organization", back_populates="projects")

class TenantUsage(Base):
    """Tenant usage tracking"""
    __tablename__ = 'tenant_usage'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey('organizations.id'), nullable=False)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Integer, default=0)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class MultiTenantService:
    """Multi-tenant management service"""
    
    def __init__(self):
        # Database setup
        self.db_url = os.getenv('TENANT_DB_URL', 'sqlite:///tenant.db')
        self.engine = create_engine(self.db_url)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        
        # Default subscription limits
        self.subscription_limits = {
            SubscriptionTier.FREE: TenantLimits(
                max_users=5,
                max_projects=3,
                max_scans_per_month=100,
                max_storage_gb=1,
                max_api_calls_per_hour=100,
                retention_days=30,
                advanced_features=[]
            ),
            SubscriptionTier.STARTER: TenantLimits(
                max_users=25,
                max_projects=10,
                max_scans_per_month=1000,
                max_storage_gb=10,
                max_api_calls_per_hour=1000,
                retention_days=90,
                advanced_features=['basic_analytics', 'email_notifications']
            ),
            SubscriptionTier.PROFESSIONAL: TenantLimits(
                max_users=100,
                max_projects=50,
                max_scans_per_month=10000,
                max_storage_gb=100,
                max_api_calls_per_hour=10000,
                retention_days=365,
                advanced_features=['advanced_analytics', 'custom_rules', 'api_access', 'sso']
            ),
            SubscriptionTier.ENTERPRISE: TenantLimits(
                max_users=1000,
                max_projects=500,
                max_scans_per_month=100000,
                max_storage_gb=1000,
                max_api_calls_per_hour=100000,
                retention_days=1095,  # 3 years
                advanced_features=['all_features', 'dedicated_support', 'custom_integrations', 'on_premise']
            )
        }
        
        # Initialize default organization if none exists
        self._ensure_default_organization()
    
    def _ensure_default_organization(self):
        """Ensure a default organization exists"""
        default_org = self.session.query(Organization).filter_by(slug='default').first()
        if not default_org:
            default_org = Organization(
                name='Default Organization',
                slug='default',
                status=TenantStatus.ACTIVE.value,
                subscription_tier=SubscriptionTier.ENTERPRISE.value,
                subscription_start=datetime.utcnow(),
                subscription_end=datetime.utcnow() + timedelta(days=365 * 10)  # 10 years
            )
            self.session.add(default_org)
            self.session.commit()
            logging.info("Created default organization")
    
    def create_organization(self, org_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new organization"""
        try:
            # Generate unique slug
            base_slug = org_data['name'].lower().replace(' ', '-').replace('_', '-')
            slug = base_slug
            counter = 1
            while self.session.query(Organization).filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            # Set trial period for new organizations
            trial_days = int(os.getenv('TRIAL_PERIOD_DAYS', '14'))
            
            organization = Organization(
                name=org_data['name'],
                slug=slug,
                domain=org_data.get('domain'),
                status=TenantStatus.TRIAL.value,
                subscription_tier=SubscriptionTier.FREE.value,
                trial_end=datetime.utcnow() + timedelta(days=trial_days),
                settings=org_data.get('settings', {}),
                limits=self._get_subscription_limits(SubscriptionTier.FREE)
            )
            
            self.session.add(organization)
            self.session.commit()
            
            # Create admin user if provided
            if org_data.get('admin_user_id'):
                self.add_user_to_organization(
                    organization.id,
                    org_data['admin_user_id'],
                    'admin'
                )
            
            return self._organization_to_dict(organization)
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to create organization: {e}")
            raise
    
    def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Get organization by ID"""
        organization = self.session.query(Organization).filter_by(id=org_id).first()
        if organization:
            return self._organization_to_dict(organization)
        return None
    
    def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Get organization by slug"""
        organization = self.session.query(Organization).filter_by(slug=slug).first()
        if organization:
            return self._organization_to_dict(organization)
        return None
    
    def update_organization(self, org_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update organization"""
        try:
            organization = self.session.query(Organization).filter_by(id=org_id).first()
            if not organization:
                raise ValueError("Organization not found")
            
            # Update allowed fields
            allowed_fields = ['name', 'domain', 'settings']
            for field in allowed_fields:
                if field in update_data:
                    setattr(organization, field, update_data[field])
            
            organization.updated_at = datetime.utcnow()
            self.session.commit()
            
            return self._organization_to_dict(organization)
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to update organization: {e}")
            raise
    
    def update_subscription(self, org_id: str, tier: SubscriptionTier, duration_days: int = 365) -> Dict[str, Any]:
        """Update organization subscription"""
        try:
            organization = self.session.query(Organization).filter_by(id=org_id).first()
            if not organization:
                raise ValueError("Organization not found")
            
            organization.subscription_tier = tier.value
            organization.subscription_start = datetime.utcnow()
            organization.subscription_end = datetime.utcnow() + timedelta(days=duration_days)
            organization.status = TenantStatus.ACTIVE.value
            organization.limits = self._get_subscription_limits(tier)
            organization.updated_at = datetime.utcnow()
            
            self.session.commit()
            
            return self._organization_to_dict(organization)
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to update subscription: {e}")
            raise
    
    def add_user_to_organization(self, org_id: str, user_id: str, role: str = 'member') -> Dict[str, Any]:
        """Add user to organization"""
        try:
            # Check if user is already in organization
            existing = self.session.query(OrganizationUser).filter_by(
                organization_id=org_id,
                user_id=user_id
            ).first()
            
            if existing:
                raise ValueError("User already in organization")
            
            # Check user limits
            organization = self.session.query(Organization).filter_by(id=org_id).first()
            if not organization:
                raise ValueError("Organization not found")
            
            current_users = self.session.query(OrganizationUser).filter_by(
                organization_id=org_id,
                status='active'
            ).count()
            
            limits = self._get_subscription_limits(SubscriptionTier(organization.subscription_tier))
            if current_users >= limits.max_users:
                raise ValueError("User limit exceeded for subscription tier")
            
            org_user = OrganizationUser(
                organization_id=org_id,
                user_id=user_id,
                role=role,
                permissions=self._get_default_permissions(role)
            )
            
            self.session.add(org_user)
            self.session.commit()
            
            return {
                'id': org_user.id,
                'organization_id': org_user.organization_id,
                'user_id': org_user.user_id,
                'role': org_user.role,
                'status': org_user.status,
                'joined_at': org_user.joined_at.isoformat(),
                'permissions': org_user.permissions
            }
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to add user to organization: {e}")
            raise
    
    def remove_user_from_organization(self, org_id: str, user_id: str):
        """Remove user from organization"""
        try:
            org_user = self.session.query(OrganizationUser).filter_by(
                organization_id=org_id,
                user_id=user_id
            ).first()
            
            if org_user:
                self.session.delete(org_user)
                self.session.commit()
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to remove user from organization: {e}")
            raise
    
    def get_user_organizations(self, user_id: str) -> List[Dict[str, Any]]:
        """Get organizations for a user"""
        org_users = self.session.query(OrganizationUser).filter_by(
            user_id=user_id,
            status='active'
        ).all()
        
        organizations = []
        for org_user in org_users:
            org_dict = self._organization_to_dict(org_user.organization)
            org_dict['user_role'] = org_user.role
            org_dict['user_permissions'] = org_user.permissions
            organizations.append(org_dict)
        
        return organizations
    
    def check_user_permission(self, org_id: str, user_id: str, permission: str) -> bool:
        """Check if user has specific permission in organization"""
        org_user = self.session.query(OrganizationUser).filter_by(
            organization_id=org_id,
            user_id=user_id,
            status='active'
        ).first()
        
        if not org_user:
            return False
        
        # Admin has all permissions
        if org_user.role == 'admin':
            return True
        
        # Check specific permissions
        return permission in org_user.permissions
    
    def create_project(self, org_id: str, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create project in organization"""
        try:
            # Check project limits
            organization = self.session.query(Organization).filter_by(id=org_id).first()
            if not organization:
                raise ValueError("Organization not found")
            
            current_projects = self.session.query(Project).filter_by(
                organization_id=org_id,
                status='active'
            ).count()
            
            limits = self._get_subscription_limits(SubscriptionTier(organization.subscription_tier))
            if current_projects >= limits.max_projects:
                raise ValueError("Project limit exceeded for subscription tier")
            
            project = Project(
                organization_id=org_id,
                name=project_data['name'],
                description=project_data.get('description'),
                repository_url=project_data.get('repository_url'),
                settings=project_data.get('settings', {})
            )
            
            self.session.add(project)
            self.session.commit()
            
            return {
                'id': project.id,
                'organization_id': project.organization_id,
                'name': project.name,
                'description': project.description,
                'repository_url': project.repository_url,
                'status': project.status,
                'created_at': project.created_at.isoformat(),
                'settings': project.settings
            }
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to create project: {e}")
            raise
    
    def track_usage(self, org_id: str, metric_name: str, value: int = 1):
        """Track usage metrics for organization"""
        try:
            # Get current month period
            now = datetime.utcnow()
            period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if now.month == 12:
                period_end = period_start.replace(year=now.year + 1, month=1) - timedelta(seconds=1)
            else:
                period_end = period_start.replace(month=now.month + 1) - timedelta(seconds=1)
            
            # Find or create usage record
            usage = self.session.query(TenantUsage).filter_by(
                organization_id=org_id,
                metric_name=metric_name,
                period_start=period_start
            ).first()
            
            if usage:
                usage.metric_value += value
            else:
                usage = TenantUsage(
                    organization_id=org_id,
                    metric_name=metric_name,
                    metric_value=value,
                    period_start=period_start,
                    period_end=period_end
                )
                self.session.add(usage)
            
            self.session.commit()
            
        except Exception as e:
            self.session.rollback()
            logging.error(f"Failed to track usage: {e}")
    
    def check_usage_limits(self, org_id: str) -> Dict[str, Any]:
        """Check current usage against limits"""
        organization = self.session.query(Organization).filter_by(id=org_id).first()
        if not organization:
            return {}
        
        limits = self._get_subscription_limits(SubscriptionTier(organization.subscription_tier))
        
        # Get current month usage
        now = datetime.utcnow()
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        usage_records = self.session.query(TenantUsage).filter_by(
            organization_id=org_id,
            period_start=period_start
        ).all()
        
        current_usage = {}
        for record in usage_records:
            current_usage[record.metric_name] = record.metric_value
        
        # Calculate usage percentages
        usage_status = {
            'scans': {
                'current': current_usage.get('scans', 0),
                'limit': limits.max_scans_per_month,
                'percentage': (current_usage.get('scans', 0) / limits.max_scans_per_month) * 100
            },
            'api_calls': {
                'current': current_usage.get('api_calls', 0),
                'limit': limits.max_api_calls_per_hour,
                'percentage': (current_usage.get('api_calls', 0) / limits.max_api_calls_per_hour) * 100
            },
            'storage': {
                'current': current_usage.get('storage_gb', 0),
                'limit': limits.max_storage_gb,
                'percentage': (current_usage.get('storage_gb', 0) / limits.max_storage_gb) * 100
            }
        }
        
        return usage_status
    
    def _get_subscription_limits(self, tier: SubscriptionTier) -> Dict[str, Any]:
        """Get limits for subscription tier"""
        limits = self.subscription_limits.get(tier)
        if limits:
            return {
                'max_users': limits.max_users,
                'max_projects': limits.max_projects,
                'max_scans_per_month': limits.max_scans_per_month,
                'max_storage_gb': limits.max_storage_gb,
                'max_api_calls_per_hour': limits.max_api_calls_per_hour,
                'retention_days': limits.retention_days,
                'advanced_features': limits.advanced_features
            }
        return {}
    
    def _get_default_permissions(self, role: str) -> List[str]:
        """Get default permissions for role"""
        permissions = {
            'admin': [
                'manage_organization',
                'manage_users',
                'manage_projects',
                'view_analytics',
                'manage_settings',
                'scan_code',
                'view_vulnerabilities',
                'manage_compliance'
            ],
            'manager': [
                'manage_projects',
                'view_analytics',
                'scan_code',
                'view_vulnerabilities',
                'manage_compliance'
            ],
            'developer': [
                'scan_code',
                'view_vulnerabilities',
                'view_own_projects'
            ],
            'viewer': [
                'view_vulnerabilities',
                'view_own_projects'
            ],
            'member': [
                'scan_code',
                'view_vulnerabilities'
            ]
        }
        
        return permissions.get(role, permissions['member'])
    
    def _organization_to_dict(self, organization: Organization) -> Dict[str, Any]:
        """Convert organization model to dictionary"""
        return {
            'id': organization.id,
            'name': organization.name,
            'slug': organization.slug,
            'domain': organization.domain,
            'status': organization.status,
            'subscription_tier': organization.subscription_tier,
            'created_at': organization.created_at.isoformat(),
            'updated_at': organization.updated_at.isoformat(),
            'subscription_start': organization.subscription_start.isoformat() if organization.subscription_start else None,
            'subscription_end': organization.subscription_end.isoformat() if organization.subscription_end else None,
            'trial_end': organization.trial_end.isoformat() if organization.trial_end else None,
            'settings': organization.settings,
            'limits': organization.limits,
            'user_count': len(organization.users),
            'project_count': len(organization.projects)
        }

# Initialize multi-tenant service
multi_tenant_service = MultiTenantService()

def require_organization():
    """Decorator to require organization context"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            org_id = request.headers.get('X-Organization-ID') or request.args.get('organization_id')
            if not org_id:
                return jsonify({'error': 'Organization ID required'}), 400
            
            organization = multi_tenant_service.get_organization(org_id)
            if not organization:
                return jsonify({'error': 'Organization not found'}), 404
            
            g.organization_id = org_id
            g.organization = organization
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = getattr(g, 'user_id', None)
            org_id = getattr(g, 'organization_id', None)
            
            if not user_id or not org_id:
                return jsonify({'error': 'Authentication and organization context required'}), 401
            
            if not multi_tenant_service.check_user_permission(org_id, user_id, permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

@multi_tenant_bp.route('/organizations', methods=['POST'])
def create_organization():
    """Create new organization"""
    data = request.get_json()
    
    try:
        organization = multi_tenant_service.create_organization(data)
        return jsonify(organization), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@multi_tenant_bp.route('/organizations/<org_id>', methods=['GET'])
def get_organization(org_id):
    """Get organization details"""
    organization = multi_tenant_service.get_organization(org_id)
    if organization:
        return jsonify(organization)
    return jsonify({'error': 'Organization not found'}), 404

@multi_tenant_bp.route('/organizations/<org_id>', methods=['PUT'])
@require_organization()
@require_permission('manage_organization')
def update_organization(org_id):
    """Update organization"""
    data = request.get_json()
    
    try:
        organization = multi_tenant_service.update_organization(org_id, data)
        return jsonify(organization)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@multi_tenant_bp.route('/organizations/<org_id>/users', methods=['POST'])
@require_organization()
@require_permission('manage_users')
def add_user_to_organization(org_id):
    """Add user to organization"""
    data = request.get_json()
    
    try:
        user = multi_tenant_service.add_user_to_organization(
            org_id,
            data['user_id'],
            data.get('role', 'member')
        )
        return jsonify(user), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@multi_tenant_bp.route('/organizations/<org_id>/users/<user_id>', methods=['DELETE'])
@require_organization()
@require_permission('manage_users')
def remove_user_from_organization(org_id, user_id):
    """Remove user from organization"""
    try:
        multi_tenant_service.remove_user_from_organization(org_id, user_id)
        return jsonify({'message': 'User removed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@multi_tenant_bp.route('/organizations/<org_id>/projects', methods=['POST'])
@require_organization()
@require_permission('manage_projects')
def create_project(org_id):
    """Create project in organization"""
    data = request.get_json()
    
    try:
        project = multi_tenant_service.create_project(org_id, data)
        return jsonify(project), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@multi_tenant_bp.route('/organizations/<org_id>/usage', methods=['GET'])
@require_organization()
def get_usage_status(org_id):
    """Get organization usage status"""
    usage_status = multi_tenant_service.check_usage_limits(org_id)
    return jsonify(usage_status)

@multi_tenant_bp.route('/organizations/<org_id>/subscription', methods=['PUT'])
@require_organization()
@require_permission('manage_organization')
def update_subscription(org_id):
    """Update organization subscription"""
    data = request.get_json()
    
    try:
        tier = SubscriptionTier(data['tier'])
        duration = data.get('duration_days', 365)
        
        organization = multi_tenant_service.update_subscription(org_id, tier, duration)
        return jsonify(organization)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@multi_tenant_bp.route('/user/organizations', methods=['GET'])
def get_user_organizations():
    """Get organizations for current user"""
    user_id = getattr(g, 'user_id', None)
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 401
    
    organizations = multi_tenant_service.get_user_organizations(user_id)
    return jsonify({'organizations': organizations})

# Export the multi-tenant service
__all__ = ['multi_tenant_bp', 'multi_tenant_service', 'require_organization', 'require_permission']

