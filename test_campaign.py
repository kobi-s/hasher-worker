#!/usr/bin/env python3
"""
Test script for campaign processing functionality
"""

import json
import asyncio
import aiohttp
from pathlib import Path

async def test_campaign_processing():
    """Test the campaign processing endpoint."""
    
    # Test configuration
    test_config = {
        "campaignId": "test-campaign-123",
        "name": "Test Campaign",
        "hashType": 1000,
        "hashTypeName": "NTLM",
        "attackMode": 0,
        "wordlist": "test-wordlist",
        "increment": False,
        "optimizedKernelEnable": True,
        "statusTimer": 5,
        "potfilePath": "test_cracked.txt",
        "hashFile": {
            "bucket": "",
            "key": "",
            "location": "https://httpbin.org/bytes/1024"  # Test URL
        },
        "ruleFiles": [
            {
                "bucket": "test-bucket",
                "key": "rules/test.rule",
                "location": "https://httpbin.org/bytes/512",  # Test URL
                "filename": "test.rule",
                "_id": "test-rule-123"
            }
        ],
        "controlServer": "localhost",
        "controlPort": 8080,
        "settings": {
            "gpuModel": "v100",
            "maxRuntime": 24,
            "maxCost": 100,
            "maxInstances": 4,
            "region": "auto",
            "useSpotInstances": True,
            "debugOutput": False,
            "enableBenchmark": False
        }
    }
    
    # Write test config
    with open("test-campaign-config.json", "w") as f:
        json.dump(test_config, f, indent=2)
    
    print("Test campaign configuration created: test-campaign-config.json")
    
    # Test server endpoints
    base_url = "http://localhost:4444"
    
    async with aiohttp.ClientSession() as session:
        try:
            # Test health endpoint
            print("\n1. Testing health endpoint...")
            async with session.get(f"{base_url}/health") as response:
                if response.status == 200:
                    health_data = await response.json()
                    print(f"✓ Health check passed: {health_data}")
                else:
                    print(f"✗ Health check failed: {response.status}")
            
            # Test hello endpoint
            print("\n2. Testing hello endpoint...")
            hello_data = {"message": "Test message", "timestamp": "2024-01-01T12:00:00Z"}
            async with session.post(f"{base_url}/hello", json=hello_data) as response:
                if response.status == 200:
                    hello_response = await response.json()
                    print(f"✓ Hello endpoint passed: {hello_response}")
                else:
                    print(f"✗ Hello endpoint failed: {response.status}")
            
            # Test logs endpoint
            print("\n3. Testing logs endpoint...")
            async with session.get(f"{base_url}/logs") as response:
                if response.status == 200:
                    logs_data = await response.json()
                    print(f"✓ Logs endpoint passed: Found {len(logs_data.get('all_log_files', []))} log files")
                else:
                    print(f"✗ Logs endpoint failed: {response.status}")
            
            # Test campaign processing (this will fail without actual files, but tests the endpoint)
            print("\n4. Testing campaign processing endpoint...")
            async with session.post(f"{base_url}/process-campaign") as response:
                if response.status == 404:
                    print("✓ Campaign processing endpoint exists (expected 404 for missing config file)")
                else:
                    print(f"Campaign processing response: {response.status}")
                    try:
                        result = await response.json()
                        print(f"Result: {result}")
                    except:
                        pass
            
        except aiohttp.ClientConnectorError:
            print("✗ Could not connect to server. Make sure the server is running on localhost:4444")
        except Exception as e:
            print(f"✗ Error during testing: {str(e)}")

def main():
    """Main function."""
    print("Hashcat Worker Server - Campaign Processing Test")
    print("=" * 50)
    
    # Check if server files exist
    if not Path("run.py").exists():
        print("✗ run.py not found. Make sure you're in the correct directory.")
        return
    
    if not Path("requirements.txt").exists():
        print("✗ requirements.txt not found. Make sure you're in the correct directory.")
        return
    
    print("✓ Server files found")
    
    # Run async test
    asyncio.run(test_campaign_processing())
    
    print("\n" + "=" * 50)
    print("Test completed!")
    print("\nTo start the server:")
    print("python run.py")
    print("\nTo start with auto-campaign processing:")
    print("python run.py --auto-start")

if __name__ == "__main__":
    main() 