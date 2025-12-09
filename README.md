# FinTech Wallet API

A robust, high-performance wallet system API built with **FastAPI**. This application handles user authentication via Google OAuth, secure wallet-to-wallet transfers, and deposits via Paystack integration. It also features a sophisticated API Key management system for service-to-service communication.

## 🚀 Features

### Authentication & Security
- **Google OAuth 2.0**: Secure user sign-in and account creation.
- **JWT Authentication**: Stateless session management for users.
- **API Key System**: 
  - Generate keys with specific permissions (e.g., `read`, `deposit`, `transfer`).
  - Enforce key expiration (e.g., 1H, 1D, 1M).
  - Secure key hashing (bcrypt).
  - Key rollover mechanism for expired keys.
  - Limit of 5 active keys per user.

### Wallet Management
- **Automatic Wallet Creation**: Users get a wallet immediately upon sign-up.
- **Balance Check**: Real-time balance retrieval.
- **Transaction History**: View deposit and transfer history.

### Transactions
- **Deposits (Paystack)**: 
  - Initialize transactions via Paystack API.
  - **Secure Webhook**: Verifies payment authenticity using HMAC SHA512 signature before crediting wallets.
  - Idempotency checks to prevent double-crediting.
- **Transfers**: 
  - Secure wallet-to-wallet transfers.
  - **Concurrency Control**: Uses database row locking (`SELECT FOR UPDATE`) to prevent race conditions and double-spending.
  - Atomic database transactions.

## 🛠️ Tech Stack

- **Framework**: FastAPI
- **Language**: Python 3.11+
- **Database**: SQLite (Default) / PostgreSQL (Production ready via SQLAlchemy)
- **ORM**: SQLAlchemy
- **Authentication**: Authlib (Google), Python-Jose (JWT), Passlib (Hashing)
- **HTTP Client**: HTTPX (Async)
- **Containerization**: Docker

## 📋 Prerequisites

- Python 3.11 or higher
- Docker (Optional, for containerized deployment)
- A Paystack Account (for Secret Key)
- Google Cloud Console Project (for OAuth Credentials)

## ⚙️ Installation & Local Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd hng-8
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**
   Create a `.env` file in the root directory and populate it with your credentials:
   ```env
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   SECRET_KEY=your_super_secret_jwt_key
   PAYSTACK_SECRET_KEY=your_paystack_secret_key
   ```

5. **Run the Application**
   ```bash
   uvicorn app.main:app --reload
   ```
   The API will be available at `http://127.0.0.1:8000`.

## 🐳 Docker Setup

1. **Build the image**
   ```bash
   docker build -t wallet-api .
   ```

2. **Run the container**
   ```bash
   docker run -p 8000:8000 --env-file .env wallet-api
   ```

## 📖 API Documentation

Once the app is running, visit the interactive documentation:
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

### Key Endpoints

#### Authentication
- `GET /auth/google`: Redirects to Google Login.
- `GET /auth/google/callback`: Handles return from Google, creates user/wallet, returns JWT.

#### API Keys
- `POST /keys/create`: Create a new API key with expiry (e.g., "1M") and permissions.
- `POST /keys/rollover`: Replace an expired key with a new one.

#### Wallet & Transactions
- `GET /wallet/balance`: Get current balance.
- `POST /wallet/deposit`: Initialize a Paystack deposit.
- `POST /wallet/transfer`: Transfer funds to another wallet.
- `POST /wallet/paystack/webhook`: Endpoint for Paystack to confirm payments (Publicly accessible).

## 🧪 Testing

To run tests (if configured):
```bash
pytest
```

## 🔒 Security Notes

- **Secrets**: Never commit your `.env` file.
- **Webhooks**: The webhook endpoint verifies the `x-paystack-signature` header to ensure requests actually come from Paystack.
- **Concurrency**: Financial transactions use database locking to ensure data integrity during high traffic.