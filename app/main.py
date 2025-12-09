import os
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware

# Import your database and models to create tables
from app.database import engine, Base
# Import the auth router we just created
from app.routes import auth, keys, transactions , wallet

# 1. Create the Database Tables
# This creates the users, wallets, transactions, and api_keys tables if they don't exist
Base.metadata.create_all(bind=engine)

# 2. Initialize the FastAPI App
app = FastAPI(
    title="FinTech Wallet API",
    description="API for wallet management and Google OAuth authentication",
    version="1.0.0"
)

# 3. Add Session Middleware (CRITICAL for Google OAuth)
# Authlib needs this to store a temporary "state" token during the redirect
# to prevent CSRF attacks.
SECRET_KEY = os.getenv("SECRET_KEY", "replace_this_with_a_secure_random_string")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# 4. Add CORS (Optional but recommended for frontend connection)
# Allow your frontend (e.g., React/Vue running on localhost:3000) to hit this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 5. Include the Routers
app.include_router(auth.router)
app.include_router(keys.router)
app.include_router(transactions.router)
app.include_router(wallet.router)
# 6. Root Endpoint (Health Check)
@app.get("/")
def read_root():
    return {"status": "healthy", "message": "Wallet API is running"}

# Note: To run this, use the command:
# uvicorn main:app --reload