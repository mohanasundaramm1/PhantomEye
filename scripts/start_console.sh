#!/bin/bash

# Elite CTI Console Control Script

echo "🛡️ INITIALIZING CYBER SENTINEL COMMAND CENTER..."

# 1. Start FastAPI Backend
echo "📡 STARTING INTELLIGENCE BACKEND..."
source .venv/bin/activate
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# 2. Start Next.js Frontend
echo "🖥️ STARTING COMMAND CONSOLE UI..."
cd web
npm run dev -- -p 3000 &
FRONTEND_PID=$!

function cleanup {
    echo "🛑 SHUTTING DOWN COMMAND CENTER..."
    kill $BACKEND_PID
    kill $FRONTEND_PID
    exit
}

trap cleanup SIGINT

echo "🚀 CONSOLE ACTIVE:"
echo "   - BACKEND: http://localhost:8000"
echo "   - CONSOLE: http://localhost:3000"

wait
