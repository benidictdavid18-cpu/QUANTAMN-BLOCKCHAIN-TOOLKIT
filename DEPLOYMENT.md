# Deployment Guide

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Modern web browser (Chrome, Firefox, Edge)
- (Optional) Blockchain wallet with Polygon/Ethereum testnet funds

## Local Deployment

### Step 1: Install Dependencies

```bash
cd quantum-blockchain-toolkit
pip install -r requirements.txt
```

### Step 2: Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and add your configuration
# For testing, you can leave default values
```

### Step 3: Start Backend Server

```bash
cd backend
python app.py
```

The backend API will start on `http://localhost:8000`

### Step 4: Open Frontend

Open `frontend/index.html` in your web browser, or serve it using a simple HTTP server:

```bash
cd frontend
python -m http.server 8080
```

Then navigate to `http://localhost:8080`

## Production Deployment

### Using Docker (Recommended)

```bash
docker build -t quantum-blockchain-toolkit .
docker run -p 8000:8000 -p 8080:8080 quantum-blockchain-toolkit
```

### Using Cloud Platform

#### Heroku

```bash
heroku create quantum-toolkit
git push heroku main
```

#### AWS EC2

1. Launch EC2 instance (Ubuntu 20.04+)
2. SSH into instance
3. Clone repository
4. Install dependencies
5. Configure nginx as reverse proxy
6. Set up SSL with Let's Encrypt
7. Run backend with systemd service

#### Google Cloud Platform

```bash
gcloud app deploy
```

### Blockchain Deployment

A registry contract is already deployed on Sepolia at
`0x9F7946197AD3693e79948a229AAf177fAC3644Bf`, which is the default. It exposes a
single function:

```solidity
function storeProof(string scanId, string company, uint256 riskScore, bytes32 dataHash)
```

To use your own deployment, deploy a contract with that signature (Remix or
Foundry) and set `CONTRACT_ADDRESS` in `backend/.env`.

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| BLOCKCHAIN_PRIVATE_KEY | Wallet private key for anchoring transactions | No — `/api/blockchain/*` returns 503 without it |
| WEB3_RPC_URL | Blockchain RPC endpoint | No (default: Sepolia) |
| CONTRACT_ADDRESS | Registry contract address | No (default: see above) |
| CHAIN_ID | EVM chain id | No (default: 11155111) |
| TOOLKIT_API_KEY | Required in `X-API-Key` for gas-spending routes | **Yes for public deployments** |
| ALLOWED_ORIGINS | Comma-separated CORS origins | No (default: `*`) |
| PORT | Backend port | No (default: 8000) |

## Testing the Application

1. Navigate to the frontend in your browser
2. Fill in company information
3. Upload a sample smart contract (see `examples/` folder)
4. Click "Scan for Vulnerabilities"
5. Review results and generate reports

## Troubleshooting

### Backend not starting
- Check if port 8000 is already in use
- Verify all dependencies are installed
- Check Python version (3.8+)

### Frontend can't connect to backend
- Ensure backend is running on port 8000
- Check CORS settings in `app.py`
- Verify API_BASE_URL in `frontend/app.js`

### Blockchain transactions failing
- Ensure you have testnet funds (Mumbai MATIC)
- Verify RPC URL is correct
- Check private key format

## Security Recommendations

- Never commit `.env` file to version control
- Use strong private keys in production
- Enable HTTPS in production
- Implement rate limiting
- Add authentication for production use
- Regular security audits

## Support

For issues and questions:
- GitHub Issues: [Your Repository URL]
- Email: support@quantum-toolkit.example.com
