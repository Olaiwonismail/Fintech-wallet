import enum
from datetime import datetime
from sqlalchemy import (
    Column, 
    Integer, 
    String, 
    DateTime, 
    ForeignKey, 
    DECIMAL, 
    Boolean, 
    JSON, 
    Enum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

# --- Enums for strict typing ---
class TransactionType(str, enum.Enum):
    DEPOSIT = "deposit"
    TRANSFER = "transfer"

class TransactionStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"

# --- Models ---

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    google_id = Column(String, unique=True, index=True, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    wallets = relationship("Wallet", back_populates="user")
    api_keys = relationship("ApiKey", back_populates="user")


class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    wallet_number = Column(String, unique=True, index=True, nullable=False)
    # Using DECIMAL(18, 2) ensures precision for currency (up to 999 quadrillion)
    balance = Column(DECIMAL(18, 2), default=0.00, nullable=False)
    currency = Column(String, default="NGN", nullable=False)

    # Relationships
    user = relationship("User", back_populates="wallets")
    # Transactions where this wallet is the source/owner
    transactions = relationship("Transaction", foreign_keys="[Transaction.wallet_id]", back_populates="wallet")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    wallet_id = Column(Integer, ForeignKey("wallets.id"), nullable=False)
    recipient_wallet_id = Column(Integer, ForeignKey("wallets.id"), nullable=True)
    
    # Enum types for data integrity
    type = Column(Enum(TransactionType), nullable=False)
    amount = Column(DECIMAL(18, 2), nullable=False)
    reference = Column(String, unique=True, index=True, nullable=False)
    status = Column(Enum(TransactionStatus), default=TransactionStatus.PENDING, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    wallet = relationship("Wallet", foreign_keys=[wallet_id], back_populates="transactions")
    recipient_wallet = relationship("Wallet", foreign_keys=[recipient_wallet_id])


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key = Column(String, nullable=False) # Store the hashed key here
    masked_key = Column(String, nullable=False) # e.g., sk_...4321 for display
    permissions = Column(JSON, nullable=False, default=[]) # e.g., ["read", "write"]
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="api_keys")