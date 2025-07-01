"""
Enterprise SSO Authentication Service for AI Guardian
Supports LDAP, Active Directory, SAML, and OAuth2
"""

from flask import Blueprint, request, jsonify, session, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import ldap3
import jwt
import requests
from datetime import datetime, timedelta
import os
import logging
from typing import Dict, Any, Optional, List
import hashlib
import secrets
from functools import wraps
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
import base64

sso_bp = Blueprint('sso', __name__)

class SSOAuthenticationService:
    """Enterprise SSO Authentication Service"""
    
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'ai-guardian-sso-secret')
        self.jwt_expiration = int(os.getenv('JWT_EXPIRATION', '3600'))  # 1 hour
        
        # LDAP Configuration
        self.ldap_server = os.getenv('LDAP_SERVER', 'ldap://localhost:389')
        self.ldap_base_dn = os.getenv('LDAP_BASE_DN', 'dc=company,dc=com')
        self.ldap_bind_dn = os.getenv('LDAP_BIND_DN', 'cn=admin,dc=company,dc=com')
        self.ldap_bind_password = os.getenv('LDAP_BIND_PASSWORD', 'admin')
        
        # Active Directory Configuration
        self.ad_server = os.getenv('AD_SERVER', 'ldap://ad.company.com:389')
        self.ad_domain = os.getenv('AD_DOMAIN', 'COMPANY')
        self.ad_base_dn = os.getenv('AD_BASE_DN', 'DC=company,DC=com')
        
        # SAML Configuration
        self.saml_idp_url = os.getenv('SAML_IDP_URL', 'https://idp.company.com/saml')
        self.saml_sp_entity_id = os.getenv('SAML_SP_ENTITY_ID', 'ai-guardian')
        self.saml_acs_url = os.getenv('SAML_ACS_URL', 'https://ai-guardian.com/sso/saml/acs')
        
        # OAuth2 Configuration
        self.oauth2_providers = {
            'google': {
                'client_id': os.getenv('GOOGLE_CLIENT_ID'),
                'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
                'auth_url': 'https://accounts.google.com/o/oauth2/auth',
                'token_url': 'https://oauth2.googleapis.com/token',
                'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo'
            },
            'microsoft': {
                'client_id': os.getenv('MICROSOFT_CLIENT_ID'),
                'client_secret': os.getenv('MICROSOFT_CLIENT_SECRET'),
                'auth_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                'userinfo_url': 'https://graph.microsoft.com/v1.0/me'
            },
            'okta': {
                'client_id': os.getenv('OKTA_CLIENT_ID'),
                'client_secret': os.getenv('OKTA_CLIENT_SECRET'),
                'domain': os.getenv('OKTA_DOMAIN'),
                'auth_url': f"https://{os.getenv('OKTA_DOMAIN')}/oauth2/default/v1/authorize",
                'token_url': f"https://{os.getenv('OKTA_DOMAIN')}/oauth2/default/v1/token",
                'userinfo_url': f"https://{os.getenv('OKTA_DOMAIN')}/oauth2/default/v1/userinfo"
            }
        }
        
        # Session storage for multi-factor authentication
        self.mfa_sessions = {}
        
        # User role mappings
        self.role_mappings = {
            'admin': ['ai-guardian-admin', 'security-admin'],
            'analyst': ['security-analyst', 'developer'],
            'viewer': ['read-only', 'guest'],
            'developer': ['developer', 'engineer']
        }
    
    def authenticate_ldap(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user against LDAP server"""
        try:
            # Connect to LDAP server
            server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
            
            # Try to bind with user credentials
            user_dn = f"uid={username},{self.ldap_base_dn}"
            conn = ldap3.Connection(server, user_dn, password, auto_bind=True)
            
            if conn.bind():
                # Search for user attributes
                search_filter = f"(uid={username})"
                conn.search(self.ldap_base_dn, search_filter, attributes=['cn', 'mail', 'memberOf', 'department'])
                
                if conn.entries:
                    entry = conn.entries[0]
                    user_info = {
                        'username': username,
                        'email': str(entry.mail) if entry.mail else f"{username}@company.com",
                        'full_name': str(entry.cn) if entry.cn else username,
                        'department': str(entry.department) if entry.department else 'Unknown',
                        'groups': [str(group) for group in entry.memberOf] if entry.memberOf else [],
                        'auth_method': 'ldap',
                        'authenticated_at': datetime.utcnow().isoformat()
                    }
                    
                    # Map groups to roles
                    user_info['roles'] = self._map_groups_to_roles(user_info['groups'])
                    
                    conn.unbind()
                    return user_info
                
                conn.unbind()
            
        except Exception as e:
            logging.error(f"LDAP authentication failed: {e}")
        
        return None
    
    def authenticate_active_directory(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user against Active Directory"""
        try:
            # Connect to AD server
            server = ldap3.Server(self.ad_server, get_info=ldap3.ALL)
            
            # AD authentication with domain
            ad_username = f"{self.ad_domain}\\{username}"
            conn = ldap3.Connection(server, ad_username, password, auto_bind=True)
            
            if conn.bind():
                # Search for user in AD
                search_filter = f"(sAMAccountName={username})"
                conn.search(self.ad_base_dn, search_filter, 
                           attributes=['cn', 'mail', 'memberOf', 'department', 'title'])
                
                if conn.entries:
                    entry = conn.entries[0]
                    user_info = {
                        'username': username,
                        'email': str(entry.mail) if entry.mail else f"{username}@{self.ad_domain.lower()}.com",
                        'full_name': str(entry.cn) if entry.cn else username,
                        'department': str(entry.department) if entry.department else 'Unknown',
                        'title': str(entry.title) if entry.title else 'User',
                        'groups': [str(group) for group in entry.memberOf] if entry.memberOf else [],
                        'auth_method': 'active_directory',
                        'authenticated_at': datetime.utcnow().isoformat()
                    }
                    
                    # Map groups to roles
                    user_info['roles'] = self._map_groups_to_roles(user_info['groups'])
                    
                    conn.unbind()
                    return user_info
                
                conn.unbind()
            
        except Exception as e:
            logging.error(f"Active Directory authentication failed: {e}")
        
        return None
    
    def initiate_saml_auth(self, relay_state: str = None) -> str:
        """Initiate SAML authentication"""
        # Generate SAML AuthnRequest
        request_id = secrets.token_hex(16)
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        
        authn_request = f"""
        <samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{timestamp}"
            Destination="{self.saml_idp_url}"
            AssertionConsumerServiceURL="{self.saml_acs_url}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>{self.saml_sp_entity_id}</saml:Issuer>
        </samlp:AuthnRequest>
        """
        
        # Encode and compress the request
        encoded_request = base64.b64encode(authn_request.encode()).decode()
        
        # Build redirect URL
        redirect_url = f"{self.saml_idp_url}?SAMLRequest={encoded_request}"
        if relay_state:
            redirect_url += f"&RelayState={relay_state}"
        
        return redirect_url
    
    def process_saml_response(self, saml_response: str) -> Optional[Dict[str, Any]]:
        """Process SAML authentication response"""
        try:
            # Decode SAML response
            decoded_response = base64.b64decode(saml_response).decode()
            
            # Parse XML
            root = ET.fromstring(decoded_response)
            
            # Extract user attributes (simplified - real implementation would validate signatures)
            nameid = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
            attributes = root.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
            
            if nameid is not None:
                user_info = {
                    'username': nameid.text,
                    'email': nameid.text,
                    'full_name': nameid.text,
                    'auth_method': 'saml',
                    'authenticated_at': datetime.utcnow().isoformat(),
                    'groups': [],
                    'roles': ['viewer']  # Default role
                }
                
                # Extract attributes
                for attr in attributes:
                    attr_name = attr.get('Name')
                    attr_values = [val.text for val in attr.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')]
                    
                    if attr_name == 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
                        user_info['email'] = attr_values[0] if attr_values else user_info['email']
                    elif attr_name == 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name':
                        user_info['full_name'] = attr_values[0] if attr_values else user_info['full_name']
                    elif attr_name == 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role':
                        user_info['groups'] = attr_values
                        user_info['roles'] = self._map_groups_to_roles(attr_values)
                
                return user_info
            
        except Exception as e:
            logging.error(f"SAML response processing failed: {e}")
        
        return None
    
    def initiate_oauth2_auth(self, provider: str, redirect_uri: str) -> str:
        """Initiate OAuth2 authentication"""
        if provider not in self.oauth2_providers:
            raise ValueError(f"Unsupported OAuth2 provider: {provider}")
        
        config = self.oauth2_providers[provider]
        state = secrets.token_urlsafe(32)
        
        # Store state for validation
        session[f'oauth2_state_{provider}'] = state
        
        # Build authorization URL
        auth_params = {
            'client_id': config['client_id'],
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
            'state': state
        }
        
        auth_url = config['auth_url'] + '?' + '&'.join([f"{k}={v}" for k, v in auth_params.items()])
        return auth_url
    
    def process_oauth2_callback(self, provider: str, code: str, state: str, redirect_uri: str) -> Optional[Dict[str, Any]]:
        """Process OAuth2 callback"""
        try:
            # Validate state
            stored_state = session.get(f'oauth2_state_{provider}')
            if not stored_state or stored_state != state:
                logging.error("OAuth2 state validation failed")
                return None
            
            config = self.oauth2_providers[provider]
            
            # Exchange code for token
            token_data = {
                'client_id': config['client_id'],
                'client_secret': config['client_secret'],
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            }
            
            token_response = requests.post(config['token_url'], data=token_data)
            token_response.raise_for_status()
            tokens = token_response.json()
            
            # Get user info
            headers = {'Authorization': f"Bearer {tokens['access_token']}"}
            user_response = requests.get(config['userinfo_url'], headers=headers)
            user_response.raise_for_status()
            user_data = user_response.json()
            
            # Map user data
            user_info = {
                'username': user_data.get('email', user_data.get('id')),
                'email': user_data.get('email'),
                'full_name': user_data.get('name', user_data.get('displayName')),
                'auth_method': f'oauth2_{provider}',
                'authenticated_at': datetime.utcnow().isoformat(),
                'groups': [],
                'roles': ['viewer'],  # Default role
                'provider_data': user_data
            }
            
            return user_info
            
        except Exception as e:
            logging.error(f"OAuth2 callback processing failed: {e}")
        
        return None
    
    def _map_groups_to_roles(self, groups: List[str]) -> List[str]:
        """Map LDAP/AD groups to application roles"""
        roles = set()
        
        for group in groups:
            group_lower = group.lower()
            for role, group_patterns in self.role_mappings.items():
                for pattern in group_patterns:
                    if pattern.lower() in group_lower:
                        roles.add(role)
        
        return list(roles) if roles else ['viewer']
    
    def generate_jwt_token(self, user_info: Dict[str, Any]) -> str:
        """Generate JWT token for authenticated user"""
        payload = {
            'user_id': user_info['username'],
            'email': user_info['email'],
            'full_name': user_info['full_name'],
            'roles': user_info['roles'],
            'auth_method': user_info['auth_method'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.jwt_expiration)
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        return token
    
    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logging.warning("JWT token expired")
        except jwt.InvalidTokenError:
            logging.warning("Invalid JWT token")
        
        return None
    
    def require_role(self, required_roles: List[str]):
        """Decorator to require specific roles"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Get token from header
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'Authentication required'}), 401
                
                token = auth_header.split(' ')[1]
                user_data = self.validate_jwt_token(token)
                
                if not user_data:
                    return jsonify({'error': 'Invalid token'}), 401
                
                user_roles = user_data.get('roles', [])
                if not any(role in user_roles for role in required_roles):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                # Add user data to request context
                request.current_user = user_data
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator

# Initialize SSO service
sso_service = SSOAuthenticationService()

@sso_bp.route('/login/ldap', methods=['POST'])
def login_ldap():
    """LDAP authentication endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user_info = sso_service.authenticate_ldap(username, password)
    if user_info:
        token = sso_service.generate_jwt_token(user_info)
        return jsonify({
            'token': token,
            'user': user_info,
            'expires_in': sso_service.jwt_expiration
        })
    
    return jsonify({'error': 'Authentication failed'}), 401

@sso_bp.route('/login/ad', methods=['POST'])
def login_active_directory():
    """Active Directory authentication endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user_info = sso_service.authenticate_active_directory(username, password)
    if user_info:
        token = sso_service.generate_jwt_token(user_info)
        return jsonify({
            'token': token,
            'user': user_info,
            'expires_in': sso_service.jwt_expiration
        })
    
    return jsonify({'error': 'Authentication failed'}), 401

@sso_bp.route('/login/saml', methods=['GET'])
def login_saml():
    """Initiate SAML authentication"""
    relay_state = request.args.get('RelayState')
    redirect_url = sso_service.initiate_saml_auth(relay_state)
    return redirect(redirect_url)

@sso_bp.route('/saml/acs', methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service"""
    saml_response = request.form.get('SAMLResponse')
    relay_state = request.form.get('RelayState')
    
    if not saml_response:
        return jsonify({'error': 'SAML response required'}), 400
    
    user_info = sso_service.process_saml_response(saml_response)
    if user_info:
        token = sso_service.generate_jwt_token(user_info)
        
        # Redirect to frontend with token
        frontend_url = relay_state or 'https://dashboard.ai-guardian.com'
        return redirect(f"{frontend_url}?token={token}")
    
    return jsonify({'error': 'SAML authentication failed'}), 401

@sso_bp.route('/login/oauth2/<provider>', methods=['GET'])
def login_oauth2(provider):
    """Initiate OAuth2 authentication"""
    redirect_uri = request.args.get('redirect_uri', 'https://api.ai-guardian.com/sso/oauth2/callback')
    
    try:
        auth_url = sso_service.initiate_oauth2_auth(provider, redirect_uri)
        return redirect(auth_url)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@sso_bp.route('/oauth2/callback', methods=['GET'])
def oauth2_callback():
    """OAuth2 callback endpoint"""
    provider = request.args.get('provider', 'google')
    code = request.args.get('code')
    state = request.args.get('state')
    redirect_uri = request.args.get('redirect_uri', 'https://api.ai-guardian.com/sso/oauth2/callback')
    
    if not code:
        return jsonify({'error': 'Authorization code required'}), 400
    
    user_info = sso_service.process_oauth2_callback(provider, code, state, redirect_uri)
    if user_info:
        token = sso_service.generate_jwt_token(user_info)
        
        # Redirect to frontend with token
        frontend_url = 'https://dashboard.ai-guardian.com'
        return redirect(f"{frontend_url}?token={token}")
    
    return jsonify({'error': 'OAuth2 authentication failed'}), 401

@sso_bp.route('/validate', methods=['POST'])
def validate_token():
    """Validate JWT token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 400
    
    token = auth_header.split(' ')[1]
    user_data = sso_service.validate_jwt_token(token)
    
    if user_data:
        return jsonify({'valid': True, 'user': user_data})
    
    return jsonify({'valid': False, 'error': 'Invalid token'}), 401

@sso_bp.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    # In a real implementation, you might want to blacklist the token
    return jsonify({'message': 'Logged out successfully'})

@sso_bp.route('/user/profile', methods=['GET'])
@sso_service.require_role(['viewer', 'analyst', 'admin'])
def get_user_profile():
    """Get current user profile"""
    return jsonify(request.current_user)

@sso_bp.route('/admin/users', methods=['GET'])
@sso_service.require_role(['admin'])
def list_users():
    """List all users (admin only)"""
    # This would typically query a user database
    return jsonify({'message': 'User list endpoint - admin access confirmed'})

# Export the SSO service for use in other modules
__all__ = ['sso_bp', 'sso_service']

