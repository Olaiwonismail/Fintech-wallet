from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from sqlalchemy import desc, or_

from .. import models, schemas
from ..database import get_db
from ..dependencies import UnifiedAuth

router = APIRouter(
    prefix="/wallet",
    tags=["Wallet Info"]
)

# --- Endpoint 1: Get Wallet Balance ---
@router.get("/balance", response_model=schemas.WalletBalanceResponse)
async def get_wallet_balance(
    # Require "read" permission and "user" role if using API Key
    current_user: models.User = Depends(UnifiedAuth(required_permission="read")),
    db: Session = Depends(get_db)
):
    """
    Fetch the authenticated user's wallet balance.
    Accessible by: JWT (User) OR API Key (Service with 'read').
    """
    wallet = db.query(models.Wallet).filter(models.Wallet.user_id == current_user.id).first()
    
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
        
    return {"balance": wallet.balance}


# --- Endpoint 2: Get Transaction History ---
@router.get("/transactions", response_model=List[schemas.TransactionResponse])
async def get_transactions(
    # Require "read" permission and "user" role
    current_user: models.User = Depends(UnifiedAuth(required_permission="read")),
    db: Session = Depends(get_db)
):
    """
    Fetch all transactions for the user's wallet, newest first.
    """
    # 1. Get Wallet
    wallet = db.query(models.Wallet).filter(models.Wallet.user_id == current_user.id).first()
    if not wallet:
        return []

    # 2. Get Transactions
    # We filter where THIS wallet was either the sender (wallet_id) OR recipient (recipient_wallet_id)
    # Note: Your models link 'transactions' primarily to 'wallet_id'. 
    # To see incoming transfers properly, you might need an OR condition.
    # For now, we follow the basic relationship defined in your models.
    
    transactions = db.query(models.Transaction)\
        .filter(
            or_(
                models.Transaction.wallet_id == wallet.id,
                models.Transaction.recipient_wallet_id == wallet.id
            )
        )\
        .order_by(desc(models.Transaction.created_at))\
        .limit(50)\
        .all()
        
    return transactions