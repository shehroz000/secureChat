# Quick Start Guide

## Step 1: Activate Virtual Environment
```bash
source .venv/bin/activate
```

## Step 2: Start MySQL Database

### Option A: Using Docker (Recommended)
```bash
# Start Docker Desktop first, then run:
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8

# Wait a few seconds for MySQL to start, then verify:
docker ps | grep securechat-db
```

### Option B: Using Existing MySQL
Make sure MySQL is running and update `.env` with your MySQL credentials.

## Step 3: Initialize Database
```bash
python -m app.storage.db --init
```

## Step 4: Generate Certificates
```bash
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

## Step 5: Run the Server
Open Terminal 1:
```bash
source .venv/bin/activate
python -m app.server
```

You should see: "Secure Chat Server listening on localhost:8888"

## Step 6: Run the Client
Open Terminal 2:
```bash
source .venv/bin/activate
python -m app.client
```

## Step 7: Use the Chat System
1. When prompted, choose **'r'** to register or **'l'** to login
2. Enter your email, username (for registration), and password
3. Once authenticated, type messages to chat
4. Type **'quit'** to end the session

## Troubleshooting

### "Cannot connect to Docker"
- Start Docker Desktop application
- Wait for it to fully start
- Try the docker command again

### "Module not found" errors
- Make sure virtual environment is activated: `source .venv/bin/activate`
- Reinstall dependencies: `pip install -r requirements.txt`

### "Certificate not found" errors
- Make sure you completed Step 4 (Generate Certificates)
- Check that files exist: `ls -la certs/`

### "Database connection failed"
- Verify MySQL is running: `docker ps` (for Docker) or check MySQL service
- Check `.env` file has correct database credentials
- Try restarting MySQL container: `docker restart securechat-db`

### "Port already in use"
- Another process is using port 8888
- Change `SERVER_PORT` in `.env` or stop the other process

