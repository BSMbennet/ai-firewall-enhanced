# app/utils/helpers.py
import hashlib
import re
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import uuid

def generate_request_id() -> str:
    """Generate unique request ID"""
    return f"req_{uuid.uuid4().hex[:16]}"

def mask_sensitive_data(text: str, mask_ratio: float = 0.6) -> str:
    """Mask sensitive data in strings"""
    if len(text) < 4:
        return "*" * len(text)
    
    mask_length = int(len(text) * mask_ratio)
    visible_start = (len(text) - mask_length) // 2
    
    return text[:visible_start] + "*" * mask_length + text[visible_start + mask_length:]

def calculate_token_estimate(text: str) -> int:
    """Rough estimate of token count (4 chars ~ 1 token)"""
    return len(text) // 4

def validate_url(url: str) -> bool:
    """Validate URL format"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None

def safe_truncate(text: str, max_length: int = 1000, suffix: str = "...") -> str:
    """Safely truncate text without breaking words"""
    if len(text) <= max_length:
        return text
    
    truncated = text[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > 0:
        truncated = truncated[:last_space]
    
    return truncated + suffix

def parse_rate_limit_header(rate_limit: str) -> Dict[str, int]:
    """Parse RateLimit header"""
    parts = rate_limit.split(',')
    result = {}
    for part in parts:
        if '=' in part:
            key, value = part.split('=')
            result[key.strip()] = int(value.strip())
    return result

class Timer:
    """Context manager for timing operations"""
    def __init__(self):
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = datetime.utcnow()
        return self
    
    def __exit__(self, *args):
        self.end_time = datetime.utcnow()
    
    @property
    def duration_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return 0