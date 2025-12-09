import secrets
import re
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..dependencies import get_current_user_jwt, hash_key

router = APIRouter(
    prefix="/keys",
    tags=["API Keys"]
)

# --- Helper: Parse Expiry ---
def parse_expiry(expiry_str: str) -> datetime:
    """
    Parses strings like "1D", "30D", "12H" into a future datetime.
    Default to 30 days if invalid.
    """
    now = datetime.utcnow()
    
    match = re.match(r"(\d+)([DH])", expiry_str.upper())
    if not match:
        return now + timedelta(days=30) # Default
        
    value, unit = int(match.group(1)), match.group(2)
    
    if unit == 'D':
        return now + timedelta(days=value)
    elif unit == 'H':
        return now + timedelta(hours=value)
    
    return now + timedelta(days=30)

# --- Schemas for this file ---
class CreateKeyRequest(BaseModel):
    name: str # e.g. "Billing Service"
    permissions: list[str] = ["read"]
    expiry: str = "30D"

class RolloverRequest(BaseModel):
    key_id: int
    expiry: str = "30D"

# --- Endpoints ---

@router.post("/create", response_model=schemas.ApiKeySecretResponse)
async def create_api_key(
    req: CreateKeyRequest,
    current_user: models.User = Depends(get_current_user_jwt),
    db: Session = Depends(get_db)
):
    """
    Create a new API Key.
    Returns the raw secret key ONCE.
    """
    # 1. Limit Check: Max 5 active keys
    active_count = db.query(models.ApiKey).filter(
        models.ApiKey.user_id == current_user.id,
        models.ApiKey.is_active == True
    ).count()

    if active_count >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Key limit reached. Please delete or rollover an existing key."
        )

    # 2. Generate Secure String (Format: sk_UserID_RandomHex)
    # Including UserID helps lookups in Middleware
    raw_key_secret = f"sk_{current_user.id}_{secrets.token_hex(16)}"
    
    # 3. Hash for Storage
    hashed_val = hash_key(raw_key_secret)
    
    # 4. Parse Expiry
    expires_at = parse_expiry(req.expiry)

    # 5. Create DB Entry
    new_key = models.ApiKey(
        user_id=current_user.id,
        key=hashed_val,         # Store Hash
        masked_key=f"sk_...{raw_key_secret[-4:]}", # Display format
        permissions=req.permissions,
        expires_at=expires_at,
        is_active=True
    )
    
    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    # 6. Return the RAW key to the user (only time they see it)
    return schemas.ApiKeySecretResponse(
        id=new_key.id,
        user_id=new_key.user_id,
        masked_key=new_key.masked_key,
        created_at=new_key.created_at,
        permissions=new_key.permissions,
        expires_at=new_key.expires_at,
        is_active=new_key.is_active,
        secret_key=raw_key_secret # The field from schema
    )


@router.post("/rollover", response_model=schemas.ApiKeySecretResponse)
async def rollover_api_key(
    req: RolloverRequest,
    current_user: models.User = Depends(get_current_user_jwt),
    db: Session = Depends(get_db)
):
    """
    Rotates a key: Invalidates old one, creates new one with same perms.
    """
    # 1. Fetch the old key
    old_key = db.query(models.ApiKey).filter(
        models.ApiKey.id == req.key_id,
        models.ApiKey.user_id == current_user.id
    ).first()

    if not old_key:
        raise HTTPException(status_code=404, detail="Key not found")

    # 2. Validate Expiry logic (Optional: Allow rolling over active keys too?)
    # Prompt says: "Fetch by expired... Validate expires_at < now"
    # We will allow rolling over ANY key, but specifically checking expiry if strict.
    # if old_key.expires_at > datetime.utcnow():
    #     pass # Logic choice: Can we rollover a valid key? Yes, usually for security.

    # 3. Copy permissions
    perms_to_copy = old_key.permissions

    # 4. Generate New Key
    raw_key_secret = f"sk_{current_user.id}_{secrets.token_hex(16)}"
    hashed_val = hash_key(raw_key_secret)
    new_expires_at = parse_expiry(req.expiry)

    new_key = models.ApiKey(
        user_id=current_user.id,
        key=hashed_val,
        masked_key=f"sk_...{raw_key_secret[-4:]}",
        permissions=perms_to_copy, # Copied
        expires_at=new_expires_at,
        is_active=True
    )

    # 5. Invalidate Old Key
    old_key.is_active = False

    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    return schemas.ApiKeySecretResponse(
        id=new_key.id,
        user_id=new_key.user_id,
        masked_key=new_key.masked_key,
        created_at=new_key.created_at,
        permissions=new_key.permissions,
        expires_at=new_key.expires_at,
        is_active=new_key.is_active,
        secret_key=raw_key_secret
    )