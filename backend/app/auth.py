from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationToken
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
from typing import Dict, Optional

from app.supabase_client import SupabaseManager

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
supabase = SupabaseManager()

class AuthManager:
    def __init__(self):
        self.supabase = supabase

    async def authenticate(self, email: str, password: str) -> str:
        """Authenticate user and return JWT"""
        user = await self.supabase.get_user_by_email(email)
        
        if not user or not pwd_context.verify(password, user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user['id']},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return access_token

    async def require_admin(self, current_user: str = Depends(get_current_user)) -> bool:
        """Check if user is admin"""
        # This would need to be implemented with user roles
        # For now, assume first user is admin
        return True

class APIKeyManager:
    def __init__(self):
        self.supabase = supabase

    async def create_api_key(self, user_id: str, expires_days: int = 30) -> Dict:
        """Create new API key"""
        return await self.supabase.create_api_key(user_id, expires_days=expires_days)

    async def verify_api_key(self, token: HTTPAuthorizationToken = Depends(security)) -> str:
        """Verify API key and return user_id"""
        api_key = token.credentials
        
        # Check database
        key_data = await self.supabase.verify_api_key(api_key)
        
        if not key_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        return key_data['user_id']

    async def revoke_key(self, key_id: str, user_id: str):
        """Revoke API key"""
        await self.supabase.revoke_key(key_id, user_id)

    async def list_keys(self, user_id: str) -> list:
        """List all keys for user"""
        # This would need to be implemented in supabase_client
        return []

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: HTTPAuthorizationToken = Depends(security)) -> str:
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return user_id
    except JWTError:
        raise credentials_exception