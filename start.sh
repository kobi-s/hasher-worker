#!/bin/bash

# Hashcat Worker Server Startup Script

echo "Starting Hashcat Worker Server..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 is not installed"
    echo "Install with: sudo apt update && sudo apt install python3 python3-pip"
    exit 1
fi

# Check if requirements are installed
if [ ! -f "requirements.txt" ]; then
    echo "Error: requirements.txt not found"
    exit 1
fi

# Check if hashcat is installed
if ! command -v hashcat &> /dev/null; then
    echo "Warning: hashcat is not installed"
    echo "Install with: sudo apt install hashcat"
fi

# Install dependencies if needed
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Create necessary directories
mkdir -p logs work/downloads

# Check if configuration file exists
if [ ! -f "hashcat-process.json" ]; then
    echo "Warning: hashcat-process.json not found"
    echo "Please create it from hashcat-process.json.example"
    echo "cp hashcat-process.json.example hashcat-process.json"
fi

# Start the server
echo "Starting server on port 4444..."
python3 run.py --host 0.0.0.0 --port 4444 