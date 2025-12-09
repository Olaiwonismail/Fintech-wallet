import os
import hmac
import hashlib
import json
import httpx
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from .. import models, schemas
from ..database import get_db
from ..dependencies import UnifiedAuth, get_current_user_jwt
import dotenv
dotenv.load_dotenv()
router = APIRouter(
    prefix="/wallet",
    tags=["Transactions"]
)
class TransferRequest(BaseModel):
    recipient_wallet_number: str
    amount: Decimal = Field(gt=0, decimal_places=2)

# --- Configuration ---
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"

# --- Schemas for Inputs ---
class DepositRequest(BaseModel):
    amount: Decimal # User sends 5000.00 (Naira)

class PaystackResponse(BaseModel):
    authorization_url: str
    access_code: str
    reference: str


# --- Endpoint 1: Initialize Deposit ---
@router.post("/deposit", response_model=PaystackResponse)
async def initialize_deposit(
    req: DepositRequest,
    current_user: models.User = Depends(UnifiedAuth(required_permission="write", required_role="user")),
    db: Session = Depends(get_db)
):
    """
    1. Finds user's wallet.
    2. Calls Paystack API to initialize transaction.
    3. Saves PENDING transaction to DB.
    4. Returns payment URL to frontend.
    """
    # 1. Get User's Wallet
    wallet = db.query(models.Wallet).filter(models.Wallet.user_id == current_user.id).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")

    # 2. Prepare Paystack Payload
    # Paystack expects amount in Kobo (Naira * 100). Convert Decimal to int.
    amount_kobo = int(req.amount * 100)
    
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "email": current_user.email,
        "amount": amount_kobo,
        # Optional: Pass metadata to track wallet_id on Paystack side if needed
        "metadata": {"wallet_id": wallet.id, "user_id": current_user.id},
        # Optional: callback_url for frontend redirect
        # "callback_url": "http://localhost:3000/payment/callback"
    }
    
    # 3. Call Paystack
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(PAYSTACK_INIT_URL, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as e:
            raise HTTPException(status_code=400, detail=f" {str(e)}")

    if not data['status']:
        raise HTTPException(status_code=400, detail="Paystack initialization failed")

    paystack_data = data['data']
    reference = paystack_data['reference']

    # 4. Save PENDING Transaction to DB
    new_transaction = models.Transaction(
        wallet_id=wallet.id,
        recipient_wallet_id=None, # Deposit has no internal recipient
        type=models.TransactionType.DEPOSIT,
        amount=req.amount, # Store actual Naira amount
        reference=reference,
        status=models.TransactionStatus.PENDING
    )
    
    db.add(new_transaction)
    db.commit()

    return {
        "authorization_url": paystack_data['authorization_url'],
        "access_code": paystack_data['access_code'],
        "reference": reference
    }




# --- Endpoint 2: The Webhook (The "Wicked" Part) ---
@router.post("/paystack/webhook")
async def paystack_webhook(
    request: Request, 
    x_paystack_signature: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Handles payment confirmation from Paystack server-to-server.
    """
    # 1. Security: Validate Signature (HMAC SHA512)
    if not x_paystack_signature:
        raise HTTPException(status_code=401, detail="Missing signature")

    # We must read the raw bytes for HMAC verification
    body_bytes = await request.body()
    
    # Calculate expected signature
    expected_signature = hmac.new(
        key=PAYSTACK_SECRET_KEY.encode('utf-8'), 
        msg=body_bytes, 
        digestmod=hashlib.sha512
    ).hexdigest()

    if x_paystack_signature != expected_signature:
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 2. Parse Event
    try:
        event_data = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # We only care about success
    if event_data.get('event') != 'charge.success':
        # Return 200 for other events to acknowledge receipt so Paystack stops retrying
        return {"status": "ignored"}

    data = event_data['data']
    reference = data['reference']
    amount_paid_kobo = data['amount'] # Amount returned by Paystack
    amount_paid_naira = Decimal(amount_paid_kobo) / 100

    # 3. Idempotency Check & Atomic Update
    # Find the transaction
    transaction = db.query(models.Transaction).filter(
        models.Transaction.reference == reference
    ).first()

    if not transaction:
        # Case: Transaction initiated outside our system? Or DB lag?
        # Log this error. For now, we return 200 so Paystack doesn't retry forever.
        print(f"Transaction ref {reference} not found.")
        return {"status": "transaction not found"}

    # IDEMPOTENCY CHECK: If already success, stop.
    if transaction.status == models.TransactionStatus.SUCCESS:
        return {"status": "already processed"}

    # 4. Process the Value (Database Transaction)
    try:
        # A. Update Transaction Status
        transaction.status = models.TransactionStatus.SUCCESS
        
        # B. Find Wallet and Credit Balance
        wallet = db.query(models.Wallet).filter(
            models.Wallet.id == transaction.wallet_id
        ).first()
        
        if wallet:
            wallet.balance += amount_paid_naira
            
            # C. Verify amounts match (Security check)
            # Ensure the amount stored in DB matches what Paystack actually charged
            if transaction.amount != amount_paid_naira:
                # Flag for manual review if amounts differ (currency hacks etc)
                print(f"Mismatch: DB says {transaction.amount}, Paystack says {amount_paid_naira}")
                # We usually trust Paystack's amount for the wallet credit
                # but might want to flag the transaction record.

        # Commit everything atomically
        db.commit()
        
    except Exception as e:
        db.rollback()
        print(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"status": "success"}


@router.post("/transfer")
async def transfer_funds(
    req: TransferRequest,
    current_user: models.User = Depends(UnifiedAuth(required_permission="write")),
    db: Session = Depends(get_db)
):
    """
    Securely transfers funds from Current User to Recipient.
    Uses 'SELECT FOR UPDATE' to prevent Race Conditions (Double Spending).
    """
    
    # 1. Validation Logic
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    # Start a DB Transaction block explicitly
    try:
        # 2. Lock the Sender's Wallet (The Critical Concurrency Fix)
        # .with_for_update() tells the DB: "Lock this row. If anyone else tries to read/write 
        # it right now, make them wait until I finish."
        sender_wallet = db.query(models.Wallet).filter(
            models.Wallet.user_id == current_user.id
        ).with_for_update().first()

        if not sender_wallet:
            raise HTTPException(status_code=404, detail="Sender wallet not found")

        # 3. Check Balance (Safe because row is locked)
        if sender_wallet.balance < req.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Insufficient funds"
            )

        # 4. Find Recipient (No need to lock usually, unless strict accounting required)
        recipient_wallet = db.query(models.Wallet).filter(
            models.Wallet.wallet_number == req.recipient_wallet_number
        ).first()

        if not recipient_wallet:
            raise HTTPException(status_code=404, detail="Recipient wallet not found")

        # Prevent self-transfer
        if sender_wallet.id == recipient_wallet.id:
            raise HTTPException(status_code=400, detail="Cannot transfer to self")

        # 5. Execute Transfer (Atomic Operations)
        
        # A. Deduct from Sender
        sender_wallet.balance -= req.amount
        
        # B. Add to Recipient
        recipient_wallet.balance += req.amount
        
        # C. Create Transaction Record
        # We generate a unique reference for our internal records
        import uuid
        transfer_ref = f"TRF-{uuid.uuid4().hex[:12].upper()}"

        transaction_record = models.Transaction(
            wallet_id=sender_wallet.id,
            recipient_wallet_id=recipient_wallet.id,
            type=models.TransactionType.TRANSFER,
            amount=req.amount,
            reference=transfer_ref,
            status=models.TransactionStatus.SUCCESS # Instant success for internal transfers
        )
        
        db.add(transaction_record)

        # 6. Commit the entire block
        db.commit()
        db.refresh(transaction_record)

        return {
            "status": "success",
            "message": "Transfer successful",
            "data": {
                "reference": transfer_ref,
                "amount": req.amount,
                "recipient": recipient_wallet.wallet_number,
                "new_balance": sender_wallet.balance
            }
        }

    except HTTPException as he:
        # Re-raise HTTP exceptions (like 400 Insufficient Funds)
        db.rollback()
        raise he
    except Exception as e:
        # Catch unexpected DB errors
        db.rollback()
        print(f"Transfer Error: {e}")
        raise HTTPException(status_code=500, detail="Transfer failed due to server error")    
    


@router.get("/wallets", response_model=list[schemas.WalletResponse])
async def list_wallets(
    current_user: models.User = Depends(get_current_user_jwt),
    db: Session = Depends(get_db)
):
    wallets = db.query(models.Wallet).filter(models.Wallet.user_id == current_user.id).all()
    return wallets