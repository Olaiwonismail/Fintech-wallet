from fastapi import Depends, HTTPException, status, Header, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from datetime import datetime, timezone
from passlib.context import CryptContext

from . import models, database, auth
# Re-using settings from auth.py (or use generic settings)
from .routes.auth import SECRET_KEY, ALGORITHM

# --- Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 1. Helper: Verify Password/Hash ---
def verify_key_hash(plain_key, hashed_key):
    return pwd_context.verify(plain_key, hashed_key)

def hash_key(plain_key):
    return pwd_context.hash(plain_key)

# --- 2. Core: Get Current User (JWT) ---
async def get_current_user_jwt(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
):
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )

    token = creds.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user
# --- 3. Unified Auth Factory ---

class UnifiedAuth:
    """
    Validates EITHER a User JWT OR a Service API Key.
    Enforces permissions for API Keys.
    """
    def __init__(self, required_permission: str = None, required_role: str = None):
        self.required_permission = required_permission
        self.required_role = required_role

    async def __call__(
        self,
        creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
        api_key: str = Security(api_key_header),
        db: Session = Depends(get_db)
    ):
        # ---------------------------
        # A. STRATEGY 1: JWT (Bearer)
        # ---------------------------
        if creds:
            token = creds.credentials
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                user_id: int = payload.get("user_id")
                if user_id:
                    user = db.query(models.User).filter(models.User.id == user_id).first()
                    if user:
                        # JWT Users are "Admins" of their own data; we generally bypass 
                        # specific permission strings for the owner, or assume "all".
                        return user
            except JWTError:
                # If token is invalid, don't fail yet; try API key.
                pass 

        # ---------------------------
        # B. STRATEGY 2: API Key
        # ---------------------------
        if api_key:
            # 1. Parse the Key format: sk_{user_id}_{random_hex}
            try:
                parts = api_key.split("_")
                if len(parts) < 3 or parts[0] != "sk":
                    raise ValueError("Invalid format")
                user_id_str = parts[1]
                user_id = int(user_id_str)
            except (ValueError, IndexError):
                # If key format is wrong, we can't find the user efficiently.
                raise HTTPException(status_code=401, detail="Invalid API Key format")

            # 2. Fetch User's Active Keys
            # We fetch all active keys for this user to verify which one (if any) matches.
            # This is efficient because we enforced a limit of 5 keys per user.
            user_keys = db.query(models.ApiKey).filter(
                models.ApiKey.user_id == user_id,
                models.ApiKey.is_active == True
            ).all()

            found_key = None
            for k in user_keys:
                if verify_key_hash(api_key, k.key):
                    found_key = k
                    break
            
            if not found_key:
                raise HTTPException(status_code=401, detail="Invalid API Key")

            # 3. Check Expiry
            # Ensure we use timezone-aware comparison
            if found_key.expires_at:
                now = datetime.now(timezone.utc)
                expires_at_aware = found_key.expires_at.replace(tzinfo=timezone.utc)
                if expires_at_aware < now:
                    raise HTTPException(status_code=401, detail="API Key has expired")

            # 4. Check Permissions
            if self.required_permission:
                if self.required_permission not in found_key.permissions:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN, 
                        detail=f"API Key missing required permission: {self.required_permission}"
                    )

            # 4b. Check Role (uses permissions list, e.g., 'role:admin')
            if self.required_role:
                role_token = f"role:{self.required_role}"
                if role_token not in found_key.permissions:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"API Key missing required role: {self.required_role}"
                    )

            # 5. Return User
            user = db.query(models.User).filter(models.User.id == found_key.user_id).first()
            if user:
                return user

        # If we get here, neither auth method succeeded
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )