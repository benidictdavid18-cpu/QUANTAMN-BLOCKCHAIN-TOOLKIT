#!/bin/bash

# Quantum-Resistant Blockchain Security Toolkit - Startup Script

echo "========================================="
echo "Quantum-Resistant Blockchain Toolkit"
echo "========================================="
echo ""

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

echo "✓ Python 3 found"

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p uploads reports badges blockchain_proofs

# Start backend server
echo ""
echo "Starting backend server..."
cd backend
python3 app.py &
BACKEND_PID=$!

echo "✓ Backend started (PID: $BACKEND_PID)"

# Start frontend server
echo ""
echo "Starting frontend server..."
cd ../frontend
python3 -m http.server 8080 &
FRONTEND_PID=$!

echo "✓ Frontend started (PID: $FRONTEND_PID)"

echo ""
echo "========================================="
echo "Application is running!"
echo "========================================="
echo ""
echo "Frontend: http://localhost:8080"
echo "Backend API: http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop all servers"
echo ""

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
