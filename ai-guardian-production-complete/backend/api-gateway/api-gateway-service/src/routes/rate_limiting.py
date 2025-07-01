"""
Enterprise API Rate Limiting Service for AI Guardian
Provides sophisticated rate limiting with multiple strategies
"""

from flask import Blueprint, request, jsonify, g
import redis
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import logging
from functools import wraps
import os
from dataclasses import dataclass
from enum import Enum

rate_limit_bp = Blueprint('rate_limit', __name__)

class RateLimitStrategy(Enum):
    """Rate limiting strategies"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"

@dataclass
class RateLimitRule:
    """Rate limit rule configuration"""
    name: str
    strategy: RateLimitStrategy
    limit: int
    window_seconds: int
    burst_limit: Optional[int] = None
    scope: str = "global"  # global, user, organization, ip
    endpoints: List[str] = None
    priority: int = 1

@dataclass
class RateLimitResult:
    """Rate limit check result"""
    allowed: bool
    limit: int
    remaining: int
    reset_time: int
    retry_after: Optional[int] = None
    rule_name: str = ""

class EnterpriseRateLimitService:
    """Enterprise-grade rate limiting service"""
    
    def __init__(self):
        # Redis connection for distributed rate limiting
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', '6379'))
        self.redis_db = int(os.getenv('REDIS_DB', '1'))
        self.redis_password = os.getenv('REDIS_PASSWORD')
        
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
            logging.info("Connected to Redis for rate limiting")
        except Exception as e:
            logging.warning(f"Redis connection failed, using in-memory rate limiting: {e}")
            self.redis_client = None
            self.memory_store = {}
        
        # Default rate limit rules
        self.default_rules = [
            RateLimitRule(
                name="global_api_limit",
                strategy=RateLimitStrategy.SLIDING_WINDOW,
                limit=1000,
                window_seconds=3600,  # 1 hour
                scope="global"
            ),
            RateLimitRule(
                name="user_scan_limit",
                strategy=RateLimitStrategy.TOKEN_BUCKET,
                limit=100,
                window_seconds=3600,  # 1 hour
                burst_limit=20,
                scope="user",
                endpoints=["/api/scan", "/api/scan/file", "/api/scan/batch"]
            ),
            RateLimitRule(
                name="ip_auth_limit",
                strategy=RateLimitStrategy.FIXED_WINDOW,
                limit=10,
                window_seconds=300,  # 5 minutes
                scope="ip",
                endpoints=["/api/sso/login", "/api/auth/login"]
            ),
            RateLimitRule(
                name="organization_api_limit",
                strategy=RateLimitStrategy.SLIDING_WINDOW,
                limit=10000,
                window_seconds=3600,  # 1 hour
                scope="organization"
            ),
            RateLimitRule(
                name="premium_user_limit",
                strategy=RateLimitStrategy.TOKEN_BUCKET,
                limit=1000,
                window_seconds=3600,  # 1 hour
                burst_limit=100,
                scope="user",
                priority=2
            )
        ]
        
        # Load custom rules from environment or database
        self.custom_rules = self._load_custom_rules()
        
        # Combine and sort rules by priority
        all_rules = self.default_rules + self.custom_rules
        self.rules = sorted(all_rules, key=lambda x: x.priority, reverse=True)
        
        # Rate limit exemptions
        self.exempted_ips = set(os.getenv('RATE_LIMIT_EXEMPT_IPS', '').split(','))
        self.exempted_users = set(os.getenv('RATE_LIMIT_EXEMPT_USERS', '').split(','))
        
        # Metrics tracking
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rules_triggered': {}
        }
    
    def _load_custom_rules(self) -> List[RateLimitRule]:
        """Load custom rate limit rules from configuration"""
        custom_rules = []
        
        # Load from environment variable (JSON format)
        custom_rules_json = os.getenv('CUSTOM_RATE_LIMIT_RULES')
        if custom_rules_json:
            try:
                rules_data = json.loads(custom_rules_json)
                for rule_data in rules_data:
                    rule = RateLimitRule(
                        name=rule_data['name'],
                        strategy=RateLimitStrategy(rule_data['strategy']),
                        limit=rule_data['limit'],
                        window_seconds=rule_data['window_seconds'],
                        burst_limit=rule_data.get('burst_limit'),
                        scope=rule_data.get('scope', 'global'),
                        endpoints=rule_data.get('endpoints'),
                        priority=rule_data.get('priority', 1)
                    )
                    custom_rules.append(rule)
            except Exception as e:
                logging.error(f"Failed to load custom rate limit rules: {e}")
        
        return custom_rules
    
    def check_rate_limit(self, request_context: Dict[str, Any]) -> RateLimitResult:
        """Check if request should be rate limited"""
        self.metrics['total_requests'] += 1
        
        # Check exemptions
        if self._is_exempted(request_context):
            return RateLimitResult(
                allowed=True,
                limit=float('inf'),
                remaining=float('inf'),
                reset_time=0
            )
        
        # Check applicable rules
        applicable_rules = self._get_applicable_rules(request_context)
        
        for rule in applicable_rules:
            result = self._check_rule(rule, request_context)
            if not result.allowed:
                self.metrics['blocked_requests'] += 1
                self.metrics['rules_triggered'][rule.name] = self.metrics['rules_triggered'].get(rule.name, 0) + 1
                return result
        
        # If no rules block the request, allow it
        return RateLimitResult(
            allowed=True,
            limit=1000,  # Default limit for display
            remaining=999,
            reset_time=int(time.time()) + 3600
        )
    
    def _is_exempted(self, request_context: Dict[str, Any]) -> bool:
        """Check if request is exempted from rate limiting"""
        ip_address = request_context.get('ip_address')
        user_id = request_context.get('user_id')
        
        if ip_address in self.exempted_ips:
            return True
        
        if user_id in self.exempted_users:
            return True
        
        # Check for admin role
        user_roles = request_context.get('user_roles', [])
        if 'admin' in user_roles or 'super_admin' in user_roles:
            return True
        
        return False
    
    def _get_applicable_rules(self, request_context: Dict[str, Any]) -> List[RateLimitRule]:
        """Get rules applicable to the current request"""
        applicable_rules = []
        endpoint = request_context.get('endpoint', '')
        
        for rule in self.rules:
            # Check if rule applies to this endpoint
            if rule.endpoints:
                if not any(endpoint.startswith(ep) for ep in rule.endpoints):
                    continue
            
            applicable_rules.append(rule)
        
        return applicable_rules
    
    def _check_rule(self, rule: RateLimitRule, request_context: Dict[str, Any]) -> RateLimitResult:
        """Check a specific rate limit rule"""
        key = self._generate_key(rule, request_context)
        
        if rule.strategy == RateLimitStrategy.FIXED_WINDOW:
            return self._check_fixed_window(rule, key)
        elif rule.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return self._check_sliding_window(rule, key)
        elif rule.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return self._check_token_bucket(rule, key)
        elif rule.strategy == RateLimitStrategy.LEAKY_BUCKET:
            return self._check_leaky_bucket(rule, key)
        
        # Default to allowing if strategy is unknown
        return RateLimitResult(
            allowed=True,
            limit=rule.limit,
            remaining=rule.limit,
            reset_time=int(time.time()) + rule.window_seconds,
            rule_name=rule.name
        )
    
    def _generate_key(self, rule: RateLimitRule, request_context: Dict[str, Any]) -> str:
        """Generate Redis key for rate limiting"""
        scope_value = ""
        
        if rule.scope == "global":
            scope_value = "global"
        elif rule.scope == "user":
            scope_value = request_context.get('user_id', 'anonymous')
        elif rule.scope == "organization":
            scope_value = request_context.get('organization_id', 'default')
        elif rule.scope == "ip":
            scope_value = request_context.get('ip_address', 'unknown')
        
        return f"rate_limit:{rule.name}:{rule.scope}:{scope_value}"
    
    def _check_fixed_window(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check fixed window rate limit"""
        current_time = int(time.time())
        window_start = (current_time // rule.window_seconds) * rule.window_seconds
        window_key = f"{key}:{window_start}"
        
        if self.redis_client:
            try:
                # Use Redis pipeline for atomic operations
                pipe = self.redis_client.pipeline()
                pipe.incr(window_key)
                pipe.expire(window_key, rule.window_seconds)
                results = pipe.execute()
                current_count = results[0]
            except Exception as e:
                logging.error(f"Redis error in fixed window check: {e}")
                return RateLimitResult(allowed=True, limit=rule.limit, remaining=rule.limit, reset_time=current_time + rule.window_seconds)
        else:
            # In-memory fallback
            if window_key not in self.memory_store:
                self.memory_store[window_key] = {'count': 0, 'expires': window_start + rule.window_seconds}
            
            # Clean expired entries
            if self.memory_store[window_key]['expires'] <= current_time:
                self.memory_store[window_key] = {'count': 0, 'expires': window_start + rule.window_seconds}
            
            self.memory_store[window_key]['count'] += 1
            current_count = self.memory_store[window_key]['count']
        
        allowed = current_count <= rule.limit
        remaining = max(0, rule.limit - current_count)
        reset_time = window_start + rule.window_seconds
        
        return RateLimitResult(
            allowed=allowed,
            limit=rule.limit,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=reset_time - current_time if not allowed else None,
            rule_name=rule.name
        )
    
    def _check_sliding_window(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check sliding window rate limit"""
        current_time = int(time.time())
        window_start = current_time - rule.window_seconds
        
        if self.redis_client:
            try:
                # Use sorted set to track requests in sliding window
                pipe = self.redis_client.pipeline()
                
                # Remove old entries
                pipe.zremrangebyscore(key, 0, window_start)
                
                # Add current request
                pipe.zadd(key, {str(current_time): current_time})
                
                # Count requests in window
                pipe.zcard(key)
                
                # Set expiration
                pipe.expire(key, rule.window_seconds)
                
                results = pipe.execute()
                current_count = results[2]
            except Exception as e:
                logging.error(f"Redis error in sliding window check: {e}")
                return RateLimitResult(allowed=True, limit=rule.limit, remaining=rule.limit, reset_time=current_time + rule.window_seconds)
        else:
            # In-memory fallback (simplified)
            if key not in self.memory_store:
                self.memory_store[key] = []
            
            # Remove old entries
            self.memory_store[key] = [t for t in self.memory_store[key] if t > window_start]
            
            # Add current request
            self.memory_store[key].append(current_time)
            current_count = len(self.memory_store[key])
        
        allowed = current_count <= rule.limit
        remaining = max(0, rule.limit - current_count)
        reset_time = current_time + rule.window_seconds
        
        return RateLimitResult(
            allowed=allowed,
            limit=rule.limit,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=1 if not allowed else None,  # Sliding window can retry sooner
            rule_name=rule.name
        )
    
    def _check_token_bucket(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check token bucket rate limit"""
        current_time = time.time()
        bucket_key = f"{key}:bucket"
        
        if self.redis_client:
            try:
                # Get current bucket state
                bucket_data = self.redis_client.hgetall(bucket_key)
                
                if bucket_data:
                    tokens = float(bucket_data.get('tokens', rule.limit))
                    last_refill = float(bucket_data.get('last_refill', current_time))
                else:
                    tokens = rule.limit
                    last_refill = current_time
                
                # Calculate tokens to add based on time elapsed
                time_elapsed = current_time - last_refill
                tokens_to_add = (time_elapsed / rule.window_seconds) * rule.limit
                tokens = min(rule.limit, tokens + tokens_to_add)
                
                # Check if request can be served
                if tokens >= 1:
                    tokens -= 1
                    allowed = True
                else:
                    allowed = False
                
                # Update bucket state
                pipe = self.redis_client.pipeline()
                pipe.hset(bucket_key, mapping={
                    'tokens': str(tokens),
                    'last_refill': str(current_time)
                })
                pipe.expire(bucket_key, rule.window_seconds * 2)
                pipe.execute()
                
            except Exception as e:
                logging.error(f"Redis error in token bucket check: {e}")
                return RateLimitResult(allowed=True, limit=rule.limit, remaining=rule.limit, reset_time=int(current_time) + rule.window_seconds)
        else:
            # In-memory fallback
            if bucket_key not in self.memory_store:
                self.memory_store[bucket_key] = {
                    'tokens': rule.limit,
                    'last_refill': current_time
                }
            
            bucket = self.memory_store[bucket_key]
            time_elapsed = current_time - bucket['last_refill']
            tokens_to_add = (time_elapsed / rule.window_seconds) * rule.limit
            bucket['tokens'] = min(rule.limit, bucket['tokens'] + tokens_to_add)
            bucket['last_refill'] = current_time
            
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                allowed = True
                tokens = bucket['tokens']
            else:
                allowed = False
                tokens = bucket['tokens']
        
        remaining = int(tokens)
        reset_time = int(current_time + (rule.window_seconds * (1 - tokens / rule.limit)))
        
        return RateLimitResult(
            allowed=allowed,
            limit=rule.limit,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=int((1 - tokens) / (rule.limit / rule.window_seconds)) if not allowed else None,
            rule_name=rule.name
        )
    
    def _check_leaky_bucket(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check leaky bucket rate limit"""
        current_time = time.time()
        bucket_key = f"{key}:leaky"
        
        # Leaky bucket parameters
        bucket_size = rule.burst_limit or rule.limit
        leak_rate = rule.limit / rule.window_seconds  # requests per second
        
        if self.redis_client:
            try:
                bucket_data = self.redis_client.hgetall(bucket_key)
                
                if bucket_data:
                    volume = float(bucket_data.get('volume', 0))
                    last_leak = float(bucket_data.get('last_leak', current_time))
                else:
                    volume = 0
                    last_leak = current_time
                
                # Calculate leakage
                time_elapsed = current_time - last_leak
                leaked = time_elapsed * leak_rate
                volume = max(0, volume - leaked)
                
                # Check if request can be added
                if volume < bucket_size:
                    volume += 1
                    allowed = True
                else:
                    allowed = False
                
                # Update bucket state
                pipe = self.redis_client.pipeline()
                pipe.hset(bucket_key, mapping={
                    'volume': str(volume),
                    'last_leak': str(current_time)
                })
                pipe.expire(bucket_key, rule.window_seconds * 2)
                pipe.execute()
                
            except Exception as e:
                logging.error(f"Redis error in leaky bucket check: {e}")
                return RateLimitResult(allowed=True, limit=rule.limit, remaining=rule.limit, reset_time=int(current_time) + rule.window_seconds)
        else:
            # In-memory fallback
            if bucket_key not in self.memory_store:
                self.memory_store[bucket_key] = {
                    'volume': 0,
                    'last_leak': current_time
                }
            
            bucket = self.memory_store[bucket_key]
            time_elapsed = current_time - bucket['last_leak']
            leaked = time_elapsed * leak_rate
            bucket['volume'] = max(0, bucket['volume'] - leaked)
            bucket['last_leak'] = current_time
            
            if bucket['volume'] < bucket_size:
                bucket['volume'] += 1
                allowed = True
                volume = bucket['volume']
            else:
                allowed = False
                volume = bucket['volume']
        
        remaining = int(bucket_size - volume)
        reset_time = int(current_time + (volume / leak_rate))
        
        return RateLimitResult(
            allowed=allowed,
            limit=bucket_size,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=int((volume - bucket_size + 1) / leak_rate) if not allowed else None,
            rule_name=rule.name
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get rate limiting metrics"""
        return {
            'total_requests': self.metrics['total_requests'],
            'blocked_requests': self.metrics['blocked_requests'],
            'block_rate': (self.metrics['blocked_requests'] / max(1, self.metrics['total_requests'])) * 100,
            'rules_triggered': self.metrics['rules_triggered'],
            'active_rules': len(self.rules),
            'redis_connected': self.redis_client is not None
        }
    
    def add_custom_rule(self, rule: RateLimitRule):
        """Add a custom rate limit rule"""
        self.custom_rules.append(rule)
        all_rules = self.default_rules + self.custom_rules
        self.rules = sorted(all_rules, key=lambda x: x.priority, reverse=True)
    
    def remove_custom_rule(self, rule_name: str):
        """Remove a custom rate limit rule"""
        self.custom_rules = [rule for rule in self.custom_rules if rule.name != rule_name]
        all_rules = self.default_rules + self.custom_rules
        self.rules = sorted(all_rules, key=lambda x: x.priority, reverse=True)

# Initialize rate limiting service
rate_limit_service = EnterpriseRateLimitService()

def rate_limit_decorator(custom_rules: List[RateLimitRule] = None):
    """Decorator for applying rate limits to endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Build request context
            request_context = {
                'endpoint': request.endpoint,
                'method': request.method,
                'ip_address': request.remote_addr,
                'user_id': getattr(g, 'user_id', None),
                'organization_id': getattr(g, 'organization_id', None),
                'user_roles': getattr(g, 'user_roles', [])
            }
            
            # Check rate limits
            result = rate_limit_service.check_rate_limit(request_context)
            
            if not result.allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Limit: {result.limit}, Reset: {result.reset_time}',
                    'limit': result.limit,
                    'remaining': result.remaining,
                    'reset': result.reset_time,
                    'retry_after': result.retry_after
                })
                response.status_code = 429
                response.headers['X-RateLimit-Limit'] = str(result.limit)
                response.headers['X-RateLimit-Remaining'] = str(result.remaining)
                response.headers['X-RateLimit-Reset'] = str(result.reset_time)
                if result.retry_after:
                    response.headers['Retry-After'] = str(result.retry_after)
                return response
            
            # Add rate limit headers to successful responses
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(result.limit)
                response.headers['X-RateLimit-Remaining'] = str(result.remaining)
                response.headers['X-RateLimit-Reset'] = str(result.reset_time)
            
            return response
        
        return decorated_function
    return decorator

@rate_limit_bp.route('/metrics', methods=['GET'])
def get_rate_limit_metrics():
    """Get rate limiting metrics"""
    metrics = rate_limit_service.get_metrics()
    return jsonify(metrics)

@rate_limit_bp.route('/rules', methods=['GET'])
def get_rate_limit_rules():
    """Get current rate limit rules"""
    rules_data = []
    for rule in rate_limit_service.rules:
        rules_data.append({
            'name': rule.name,
            'strategy': rule.strategy.value,
            'limit': rule.limit,
            'window_seconds': rule.window_seconds,
            'burst_limit': rule.burst_limit,
            'scope': rule.scope,
            'endpoints': rule.endpoints,
            'priority': rule.priority
        })
    
    return jsonify({'rules': rules_data})

@rate_limit_bp.route('/rules', methods=['POST'])
def add_rate_limit_rule():
    """Add a custom rate limit rule"""
    data = request.get_json()
    
    try:
        rule = RateLimitRule(
            name=data['name'],
            strategy=RateLimitStrategy(data['strategy']),
            limit=data['limit'],
            window_seconds=data['window_seconds'],
            burst_limit=data.get('burst_limit'),
            scope=data.get('scope', 'global'),
            endpoints=data.get('endpoints'),
            priority=data.get('priority', 1)
        )
        
        rate_limit_service.add_custom_rule(rule)
        return jsonify({'message': 'Rule added successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@rate_limit_bp.route('/rules/<rule_name>', methods=['DELETE'])
def remove_rate_limit_rule(rule_name):
    """Remove a custom rate limit rule"""
    rate_limit_service.remove_custom_rule(rule_name)
    return jsonify({'message': 'Rule removed successfully'})

# Export the rate limiting service and decorator
__all__ = ['rate_limit_bp', 'rate_limit_service', 'rate_limit_decorator']

