#!/bin/bash

# Backend Setup

echo "Creating Python virtual environment..."
python -m venv venv

# Activate venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Setting up environment variables..."
cp .env.example .env
echo "⚠️  Please update .env with your actual API keys"

echo "Backend setup complete!"
echo "Run: python app.py"