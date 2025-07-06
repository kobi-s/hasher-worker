#!/usr/bin/env python3
"""
Test script for Hashcat Worker Server
"""

import asyncio
import aiohttp
import json
from datetime import datetime

async def test_server():
    """Test the server endpoints."""
    base_url = "http://localhost:4444"
    
    async with aiohttp.ClientSession() as session:
        print("Testing Hashcat Worker Server...")
        print("=" * 50)
        
        # Test health endpoint
        print("\n1. Testing /health endpoint...")
        try:
            async with session.get(f"{base_url}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Health check passed: {data}")
                else:
                    print(f"❌ Health check failed: {response.status}")
        except Exception as e:
            print(f"❌ Health check error: {e}")
        
        # Test hello endpoint
        print("\n2. Testing /hello endpoint...")
        try:
            payload = {
                "message": "Test message from client",
                "timestamp": datetime.now().isoformat()
            }
            async with session.post(f"{base_url}/hello", json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Hello endpoint passed: {data}")
                else:
                    print(f"❌ Hello endpoint failed: {response.status}")
        except Exception as e:
            print(f"❌ Hello endpoint error: {e}")
        
        # Test logs endpoint
        print("\n3. Testing /logs endpoint...")
        try:
            async with session.get(f"{base_url}/logs") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Logs endpoint passed")
                    print(f"   Log file: {data.get('log_file', 'N/A')}")
                    print(f"   Available logs: {len(data.get('all_log_files', []))}")
                else:
                    print(f"❌ Logs endpoint failed: {response.status}")
        except Exception as e:
            print(f"❌ Logs endpoint error: {e}")
        
        # Test process-hashcat endpoint (will fail without config file)
        print("\n4. Testing /process-hashcat endpoint...")
        try:
            async with session.post(f"{base_url}/process-hashcat") as response:
                if response.status == 404:
                    print("✅ Process-hashcat endpoint correctly reports missing config file")
                else:
                    data = await response.json()
                    print(f"✅ Process-hashcat endpoint: {data}")
        except Exception as e:
            print(f"❌ Process-hashcat endpoint error: {e}")
        
        print("\n" + "=" * 50)
        print("Test completed!")

if __name__ == "__main__":
    asyncio.run(test_server()) 