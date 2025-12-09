from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from typing import List, Optional
from datetime import datetime
from decimal import Decimal
from enum import Enum

# --- Enums (Shared with SQLAlchemy) ---
class TransactionType(str, Enum):
    DEPOSIT = "deposit"
    TRANSFER = "transfer"

class TransactionStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"

# --- Wallet Schemas ---

class WalletBase(BaseModel):
    currency: str = "NGN"

class WalletCreate(WalletBase):
    pass

class WalletResponse(WalletBase):
    id: int
    user_id: int
    wallet_number: str
    balance: Decimal = Field(decimal_places=2) # Pydantic handles Decimal serialization
    
    model_config = ConfigDict(from_attributes=True)

class WalletBalanceResponse(BaseModel):
    balance: Decimal = Field(decimal_places=2)

# --- Transaction Schemas ---

class TransactionBase(BaseModel):
    amount: Decimal = Field(gt=0, decimal_places=2) # Ensure amount is positive
    type: TransactionType
    recipient_wallet_id: Optional[int] = None

class TransactionCreate(TransactionBase):
    # Reference is typically generated backend-side, but if passed:
    pass 

class TransactionResponse(TransactionBase):
    id: int
    wallet_id: int
    reference: str
    status: TransactionStatus
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class TransferSuccessResponse(BaseModel):
    status: str
    message: str

class DepositResponse(BaseModel):
    reference: str
    authorization_url: str


# --- API Key Schemas ---

class ApiKeyBase(BaseModel):
    permissions: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    is_active: bool = True

class ApiKeyCreate(ApiKeyBase):
    pass

# Response for general listing (hides the real key, shows masked)
class ApiKeyResponse(ApiKeyBase):
    id: int
    user_id: int
    masked_key: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Special response for CREATION only (returns the raw key once)
class ApiKeySecretResponse(ApiKeyResponse):
    secret_key: str  # The unhashed key to show the user one time


# --- User Schemas ---

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    google_id: Optional[str] = None
    # Password is not in schema if using Google Auth or handled separately

class UserResponse(UserBase):
    id: int
    google_id: Optional[str] = None
    created_at: datetime
    wallets: List[WalletResponse] = Field(default_factory=list) # Nested response
    
    model_config = ConfigDict(from_attributes=True)