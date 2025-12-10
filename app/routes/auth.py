import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.config import Config
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.base_client import OAuthError
from jose import jwt
import dotenv
dotenv.load_dotenv()
# Import your specific models, schemas, and database dependencies
from .. import models, schemas
from ..database import get_db

# --- Configuration ---
# In production, these must come from environment variables
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
# GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")  # optional explicit redirect

# --- OAuth Setup ---
config_data = {
    'GOOGLE_CLIENT_ID': GOOGLE_CLIENT_ID,
    'GOOGLE_CLIENT_SECRET': GOOGLE_CLIENT_SECRET
}
starlette_config = Config(environ=config_data)
oauth = OAuth(starlette_config)

oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# --- Router Setup ---
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# --- Utility Functions ---

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generates the internal JWT for your frontend."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_wallet_number():
    """Generates a unique wallet number (e.g., W-1234567890)."""
    # In a real app, you might want a check to ensure uniqueness, 
    # though uuid collision probability is extremely low.
    return f"W-{uuid.uuid4().hex[:10].upper()}"

# --- Endpoints ---


# Add to app/routes/auth.py
@router.get("/google")
async def login_google(request: Request):
    """
    Step 1: Redirects the user to Google's OAuth 2.0 login page.
    """
    redirect_uri =str(request.url_for('auth_google_callback'))
    data = await oauth.google.authorize_redirect(request, redirect_uri)
    print(f"Redirecting to: {data.headers['location']}")
    return data.headers['location']

@router.get("/google/callback")
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    """
    Step 2: Handle the callback.
    - Verify Google Code
    - Find or Create User
    - TRIGGER: Create Wallet if New User
    - Return Internal JWT
    """
    try:
        redirect_uri = str(request.url_for('auth_google_callback'))
        token = await oauth.google.authorize_access_token(request,redirect_uri = redirect_uri)
    except OAuthError as e:
        if getattr(e, "error", "") == "mismatching_state":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OAuth state mismatch. Session cookie was missing/expired. Please retry login in the same browser tab."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.error if hasattr(e, "error") else "OAuth authorization failed"
        )

    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to retrieve user info from Google."
        )

    google_email = user_info.get('email')
    google_sub_id = user_info.get('sub') # Unique Google ID

    # 2. Check if user exists
    user = db.query(models.User).filter(models.User.email == google_email).first()

    if not user:
        # --- NEW USER FLOW ---
        # We start a transaction to ensure User and Wallet are created together.
        try:
            new_user = models.User(
                email=google_email,
                google_id=google_sub_id
            )
            db.add(new_user)
            db.flush()  # Generates the ID for new_user without committing yet

            # 3. TRIGGER: Create Wallet entry with 0.00 balance
            new_wallet = models.Wallet(
                user_id=new_user.id,
                wallet_number=generate_wallet_number(),
                balance=0.00,  # Explicitly 0.00 as requested
                currency="NGN"
            )
            db.add(new_wallet)
            
            db.commit()      # Commit both User and Wallet
            db.refresh(new_user)
            user = new_user

        except Exception as e:
            db.rollback()
            print(f"Error creating user/wallet: {str(e)}") # Added logging
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user account."
            )
    else:
        # --- EXISTING USER FLOW ---
        # If user exists but google_id is missing (e.g. they signed up differently before), link it.
        if not user.google_id:
            user.google_id = google_sub_id
            db.commit()
            db.refresh(user)

        # Safety Check: Ensure they actually have a wallet (in case of manual DB manipulation)
        if not user.wallets:
            new_wallet = models.Wallet(
                user_id=user.id,
                wallet_number=generate_wallet_number(),
                balance=0.00,
                currency="NGN"
            )
            db.add(new_wallet)
            db.commit()
  
    # 4. Generate and return your own JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "user_id": user.id}, 
        expires_delta=access_token_expires
    )
    
    # Return the token and minimal user info
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "wallet_status": "active"
    }