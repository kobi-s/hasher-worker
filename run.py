#!/usr/bin/env python3
"""
Hashcat Worker Server
A Python server for executing hashcat processes with campaign configuration and status reporting.

Features:
- Downloads campaign files from URLs
- Executes hashcat with various attack modes
- Tracks and reports hash recovery progress
- Sends real-time status updates to control server
- Monitors recovered_hashes array for new hash discoveries
"""

import os
import sys
import json
import logging
import asyncio
import aiohttp
import subprocess
import tempfile
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import argparse
import base64

# FastAPI imports
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import uvicorn

# Configure logging
def setup_logging():
    """Setup logging configuration with file and console handlers."""
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Create log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"hashcat_worker_{timestamp}.log"
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

# Initialize logger
logger = setup_logging()

# Global config file path (will be set by command line arguments)
CONFIG_FILE_PATH = "/home/ubuntu/campaigns/campaign-config.json"

# Global variables to store AWS metadata
AWS_INSTANCE_ID = None
AWS_REGION = None

async def fetch_aws_metadata():
    """Fetch AWS instance ID and region from metadata service."""
    global AWS_INSTANCE_ID, AWS_REGION
    try:
        async with aiohttp.ClientSession() as session:
            # Fetch instance ID and region concurrently
            instance_id_task = session.get('http://169.254.169.254/latest/meta-data/instance-id')
            region_task = session.get('http://169.254.169.254/latest/meta-data/placement/region')
            
            instance_id_response, region_response = await asyncio.gather(instance_id_task, region_task)
            
            # Process instance ID
            if instance_id_response.status == 200:
                AWS_INSTANCE_ID = await instance_id_response.text()
                logger.info(f"Fetched AWS instance ID: {AWS_INSTANCE_ID}")
            else:
                logger.warning(f"Failed to fetch AWS instance ID: {instance_id_response.status}")
                AWS_INSTANCE_ID = "unknown"
            
            # Process region
            if region_response.status == 200:
                AWS_REGION = await region_response.text()
                logger.info(f"Fetched AWS region: {AWS_REGION}")
            else:
                logger.warning(f"Failed to fetch AWS region: {region_response.status}")
                AWS_REGION = "unknown"
            
            return AWS_INSTANCE_ID, AWS_REGION
            
    except Exception as e:
        logger.warning(f"Error fetching AWS metadata: {str(e)}")
        AWS_INSTANCE_ID = "unknown"
        AWS_REGION = "unknown"
        return AWS_INSTANCE_ID, AWS_REGION

# Pydantic models for campaign configuration
class HashFile(BaseModel):
    bucket: str
    key: str
    location: str

class RuleFile(BaseModel):
    bucket: str
    key: str
    location: str
    filename: str
    _id: str

class Settings(BaseModel):
    gpuModel: str
    maxRuntime: int
    maxCost: float
    maxInstances: int
    region: str
    useSpotInstances: bool
    debugOutput: bool
    enableBenchmark: bool

class CampaignConfig(BaseModel):
    campaignId: str
    name: str
    hashType: int
    hashTypeName: str
    attackMode: int
    wordlist: Optional[str] = None  # optional
    increment: bool
    optimizedKernelEnable: bool
    statusTimer: int
    potfilePath: str
    hashFile: HashFile
    wordlistFiles: List[RuleFile] = []
    leftWordlistFiles: List[RuleFile] = []
    rightWordlistFiles: List[RuleFile] = []
    ruleFiles: List[RuleFile]
    controlServer: str
    controlPort: int
    settings: Settings
    associationFile: Optional[dict] = None  # <-- add this

# Pydantic models for request/response
class HelloRequest(BaseModel):
    message: str
    timestamp: Optional[str] = None

class HelloResponse(BaseModel):
    status: str
    message: str
    timestamp: str

@dataclass
class HashcatConfig:
    """Configuration for hashcat execution."""
    binary_path: str
    hash_file: str
    wordlist_file: str
    hash_type: int
    output_file: str
    attack_mode: int
    rule_files: Optional[List[str]] = None
    additional_flags: List[str] = None
    status_timer: int = 15

class HashcatWorker:
    """Main worker class for handling hashcat operations."""
    
    def __init__(self, work_dir: str = "work"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)
        self.download_dir = self.work_dir / "downloads"
        self.download_dir.mkdir(exist_ok=True)
        self.logger = logger
        self.current_process = None
        self.status_task = None
        self.last_recovered_hashes = []  # Track the last known recovered hashes for change detection
        
    async def download_file(self, url: str, filename: str) -> str:
        """Download a file from URL to local storage."""
        try:
            file_path = self.download_dir / filename
            self.logger.info(f"Downloading {url} to {file_path}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        with open(file_path, 'wb') as f:
                            f.write(await response.read())
                        self.logger.info(f"Successfully downloaded {filename}")
                        return str(file_path)
                    else:
                        raise Exception(f"Failed to download {url}: {response.status}")
        except Exception as e:
            self.logger.error(f"Error downloading {url}: {str(e)}")
            raise
    
    async def download_campaign_files(self, config: CampaignConfig) -> Dict[str, str]:
            """Download all files required for the campaign."""
            downloaded_files = {}
            
            # Download hash file
            hash_filename = f"hashes_{config.campaignId}.txt"
            hash_path = await self.download_file(config.hashFile.location, hash_filename)
            downloaded_files['hash_file'] = hash_path
            
            # Download wordlist files
            wordlist_files = []
            for wordlist_file in config.wordlistFiles:
                wordlist_path = await self.download_file(wordlist_file.location, wordlist_file.filename)
                wordlist_files.append(wordlist_path)
            
            # Use the first wordlist file as the main wordlist
            if wordlist_files:
                downloaded_files['wordlist_file'] = wordlist_files[0]
            elif config.wordlist and config.wordlist != "None":
                # Fallback to the wordlist URL if no wordlistFiles are provided
                wordlist_filename = f"wordlist_{config.campaignId}.txt"
                wordlist_path = await self.download_file(config.wordlist, wordlist_filename)
                downloaded_files['wordlist_file'] = wordlist_path
            elif config.attackMode == 9:
                # For association attack (mode 9), we don't need a wordlist file
                self.logger.info("Attack mode 9 (association) - no wordlist file needed")
            else:
                # For other attack modes, we need a wordlist but none was provided
                raise Exception(f"Wordlist is required for attack mode {config.attackMode} but none was provided")
            
            # Download left wordlist files (for combination attack)
            left_wordlist_files = []
            for left_wordlist_file in config.leftWordlistFiles:
                left_wordlist_path = await self.download_file(left_wordlist_file.location, left_wordlist_file.filename)
                left_wordlist_files.append(left_wordlist_path)
            
            if left_wordlist_files:
                downloaded_files['left_wordlist_files'] = left_wordlist_files
                # Use the first left wordlist as the main left wordlist for attack mode 1
                downloaded_files['wordlist_file2'] = left_wordlist_files[0]
            
            # Download right wordlist files (for combination attack)
            right_wordlist_files = []
            for right_wordlist_file in config.rightWordlistFiles:
                right_wordlist_path = await self.download_file(right_wordlist_file.location, right_wordlist_file.filename)
                right_wordlist_files.append(right_wordlist_path)
            
            if right_wordlist_files:
                downloaded_files['right_wordlist_files'] = right_wordlist_files
                # If we have right wordlists but no left wordlists, use the first right wordlist as wordlist_file2
                if not left_wordlist_files:
                    downloaded_files['wordlist_file2'] = right_wordlist_files[0]
            
            # Download rule files
            rule_files = []
            for rule_file in config.ruleFiles:
                rule_path = await self.download_file(rule_file.location, rule_file.filename)
                rule_files.append(rule_path)
            downloaded_files['rule_files'] = rule_files
            
            # Download association file if present
            self.logger.info(f"Checking for association file: {getattr(config, 'associationFile', None)}")
            if getattr(config, 'associationFile', None) and config.associationFile.get('location'):
                assoc_filename = config.associationFile.get('filename') or f"association_{config.campaignId}.txt"
                self.logger.info(f"Downloading association file from: {config.associationFile['location']}")
                assoc_path = await self.download_file(config.associationFile['location'], assoc_filename)
                downloaded_files['association_file'] = assoc_path
                self.logger.info(f"Successfully downloaded association file to: {assoc_path}")
            else:
                self.logger.warning("No association file found in config")
                if config.attackMode == 9:
                    self.logger.error("Association file is required for attack mode 9 but not found in config")
            
            return downloaded_files
        
    async def send_status_to_control_server(self, config: CampaignConfig, status_data: Dict[str, Any], hashcat_status: Dict[str, Any] = None):
        """Send status update to the control server. The top-level 'status' is for the instance; hashcat status JSON is sent under 'hashcatStatus'."""
        try:
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer + "/api/worker-logs"
            else:
                url = f"https://{config.controlServer}/api/worker-logs"

            payload = {
                "campaignId": config.campaignId,
                "instanceId": AWS_INSTANCE_ID,
                "region": AWS_REGION,
                "timestamp": datetime.now().isoformat(),
                "status": status_data  # This is always the instance status (e.g., 'running', 'completed', etc.)
            }
            if hashcat_status is not None:
                payload["hashcatStatus"] = hashcat_status

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 201:
                        self.logger.info(f"Status sent to control server: {status_data.get('status', 'unknown')}")
                    else:
                        self.logger.warning(f"Failed to send status to control server: {response.status}")

        except Exception as e:
            self.logger.error(f"Error sending status to control server: {str(e)}")

    async def send_progress_to_control_server(self, config: CampaignConfig, progress_data: Dict[str, Any]):
        """Send progress update to the control server."""
        try:
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer + "/api/worker-logs"
            else:
                url = f"https://{config.controlServer}:{config.controlPort}/api/worker-logs"
            
            payload = {
                "campaignId": config.campaignId,
                "instanceId": AWS_INSTANCE_ID,
                "region": AWS_REGION,
                "timestamp": datetime.now().isoformat(),
                "status": {"status": "running"},  # Always use instance status
                "hashcatStatus": progress_data  # Hashcat progress data
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 201:
                        self.logger.info(f"Progress sent to control server")
                    else:
                        self.logger.warning(f"Failed to send progress to control server: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error sending progress to control server: {str(e)}")

    def read_campaign_config(self, config_file: str) -> CampaignConfig:
        """Read and parse campaign configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            self.logger.info(f"Loaded campaign configuration from {config_file}")
            self.logger.info(f"Campaign config keys: {list(config_data.keys())}")
            if 'associationFile' in config_data:
                self.logger.info(f"Association file in config: {config_data['associationFile']}")
            else:
                self.logger.warning("No associationFile key found in campaign config")
            
            return CampaignConfig(**config_data)
        except Exception as e:
            self.logger.error(f"Error reading campaign config: {str(e)}")
            raise
    
    async def execute_hashcat(self, config: CampaignConfig, downloaded_files: Dict[str, str]) -> Dict[str, Any]:
        """Execute hashcat with the campaign configuration."""
        def is_hashcat_status_json(line: str) -> bool:
            try:
                data = json.loads(line)
                return isinstance(data, dict) and "status" in data
            except Exception:
                return False
        try:
            # Build hashcat command
            cmd = ["hashcat"]  # Assuming hashcat is in PATH
            
            # Add hash type
            cmd.extend(['-m', str(config.hashType)])
            
            # Add attack mode and files based on attack mode
            if config.attackMode == 0:  # Straight attack
                cmd.extend(['-a', '0', downloaded_files['hash_file'], downloaded_files['wordlist_file']])
            elif config.attackMode == 1:  # Combination attack
                cmd.extend(['-a', '1', downloaded_files['hash_file'], downloaded_files['wordlist_file'], downloaded_files.get('wordlist_file2', '')])
            elif config.attackMode == 3:  # Brute-force attack
                cmd.extend(['-a', '3', downloaded_files['hash_file'], '?a?a?a?a?a?a?a?a'])  # Example mask
            elif config.attackMode == 6:  # Hybrid attack
                cmd.extend(['-a', '6', downloaded_files['hash_file'], downloaded_files['wordlist_file'], '?a?a?a?a'])
            elif config.attackMode == 7:  # Hybrid attack
                cmd.extend(['-a', '7', downloaded_files['hash_file'], '?a?a?a?a', downloaded_files['wordlist_file']])
            elif config.attackMode == 9:  # Association attack
                # hashcat -a 9 <hash_file> <association_file> [other args]
                if 'association_file' not in downloaded_files:
                    raise Exception("Association file is required for attack mode 9 but was not found in downloaded files")
                cmd.extend(['-a', '9', downloaded_files['hash_file'], downloaded_files['association_file']])
            
            # Add rule files if specified
            if downloaded_files.get('rule_files'):
                for rule_file in downloaded_files['rule_files']:
                    cmd.extend(['-r', rule_file])
            
            # Add JSON output and status flags
            cmd.extend([
                '--status',
                '--status-json',
                f'--status-timer={config.statusTimer}',
                '--potfile-disable',  # Disable potfile to avoid conflicts
                '-o', config.potfilePath
            ])
            
            # Add optimization flags
            if config.optimizedKernelEnable:
                cmd.append('--optimized-kernel-enable')
            
            # Add debug output if enabled
            if config.settings.debugOutput:
                cmd.append('--debug-mode=1')
            
            self.logger.info(f"Executing hashcat command: {' '.join(cmd)}")
            
            # Execute hashcat
            self.current_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Send initial status
            await self.send_status_to_control_server(config, {
                "status": "running",
                "message": "Hashcat process started"
            })
            
            # Read stdout and stderr while process is running
            stdout_lines = []
            stderr_lines = []
            
            while self.current_process.returncode is None:
                # Read stdout
                if self.current_process.stdout:
                    try:
                        line = await asyncio.wait_for(self.current_process.stdout.readline(), timeout=0.1)
                        if line:
                            line_str = line.decode('utf-8').strip()
                            stdout_lines.append(line_str)
                            # Only send valid hashcat status-json lines
                            if is_hashcat_status_json(line_str):
                                hashcat_status_data = json.loads(line_str)
                                
                                # Check for new recovered hashes
                                newly_recovered_count = self.check_for_new_recovered_hashes(hashcat_status_data)
                                
                                # Send regular status update
                                await self.send_status_to_control_server(
                                    config,
                                    {"status": "running"},  # Always use instance status here
                                    hashcat_status=hashcat_status_data
                                )
                                await self.send_progress_to_control_server(config, hashcat_status_data)
                                
                                # Send hash recovery notification if new hashes were found
                                if newly_recovered_count > 0:
                                    await self.send_hash_recovery_notification(config, newly_recovered_count)
                    except asyncio.TimeoutError:
                        pass
                
                # Read stderr
                if self.current_process.stderr:
                    try:
                        line = await asyncio.wait_for(self.current_process.stderr.readline(), timeout=0.1)
                        if line:
                            stderr_lines.append(line.decode('utf-8').strip())
                    except asyncio.TimeoutError:
                        pass
                
                # Small delay to prevent busy waiting
                await asyncio.sleep(0.1)
            
            # If campaign completed successfully and potfile exists, send the cracked hashes with completion status
            if self.current_process.returncode == 0:
                self.logger.info("Hashcat execution completed successfully")
                
                # Check if potfile exists and send cracked hashes
                potfile_path = Path(config.potfilePath)
                if potfile_path.exists():
                    self.logger.info(f"Campaign completed successfully. Sending final cracked hashes from potfile: {config.potfilePath}")
                    # Send final cracked hashes with completed status
                    await self.send_cracked_hashes_on_completion(config)
                else:
                    self.logger.info("Campaign completed successfully but no potfile found")
                    # Send completion status without cracked hashes
                    final_status = {
                        "status": "completed",
                        "return_code": self.current_process.returncode
                    }
                    await self.send_status_to_control_server(config, final_status)
            else:
                self.logger.warning(f"Hashcat execution completed with return code {self.current_process.returncode}")
                # Send failed status
                final_status = {
                    "status": "failed",
                    "return_code": self.current_process.returncode
                }
                await self.send_status_to_control_server(config, final_status)
            
            result = {
                'return_code': self.current_process.returncode,
                'stdout': '\n'.join(stdout_lines),
                'stderr': '\n'.join(stderr_lines),
                'command': ' '.join(cmd)
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing hashcat: {str(e)}")
            raise
    
    async def process_campaign(self, config_file: str) -> Dict[str, Any]:
        """Process a complete campaign including downloads and execution."""
        try:
            # Read campaign configuration
            config = self.read_campaign_config(config_file)
            
            # Reset recovered hashes tracking for new campaign
            self.reset_recovered_hashes_tracking()
            
            # Send initial status
            await self.send_status_to_control_server(config, {
                "status": "starting",
                "message": "Campaign starting - downloading files"
            })
            
            # Download files
            downloaded_files = await self.download_campaign_files(config)
            
            # Send status after downloads
            await self.send_status_to_control_server(config, {
                "status": "files_downloaded",
                "message": "All files downloaded successfully"
            })
            
            # Execute hashcat
            result = await self.execute_hashcat(config, downloaded_files)
            
            return {
                'status': 'success',
                'campaign_id': config.campaignId,
                'execution_result': result
            }
            
        except Exception as e:
            self.logger.error(f"Error processing campaign: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'config_file': config_file
            }

    async def send_hash_recovery_notification(self, config: CampaignConfig, newly_recovered_count: int):
        """Send notification to control server about newly recovered hashes."""
        try:
            self.logger.info(f"New hashes recovered! Count: {newly_recovered_count}")
            
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer + "/api/worker-logs"
            else:
                url = f"https://{config.controlServer}/api/worker-logs"

            payload = {
                "campaignId": config.campaignId,
                "instanceId": AWS_INSTANCE_ID,
                "region": AWS_REGION,
                "timestamp": datetime.now().isoformat(),
                "status": {"status": "hash_recovered"},  # Special status for hash recovery
                "hashcatStatus": {
                    "newly_recovered_count": newly_recovered_count,
                    "total_recovered": self.last_recovered_hashes[0] if self.last_recovered_hashes else 0,
                    "total_hashes": self.last_recovered_hashes[1] if self.last_recovered_hashes else 0
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 201:
                        self.logger.info(f"Hash recovery notification sent successfully: {newly_recovered_count} hashes recovered")
                        
                        # After sending hash recovery notification, send the actual cracked hashes
                        await self.send_cracked_hashes(config, newly_recovered_count)
                    else:
                        self.logger.warning(f"Failed to send hash recovery notification: {response.status}")

        except Exception as e:
            self.logger.error(f"Error sending hash recovery notification: {str(e)}")

    async def send_cracked_hashes(self, config: CampaignConfig, newly_recovered_count: int):
        """Send the actual cracked hashes from the potfile to the control server during real-time recovery."""
        try:
            # Check if potfile exists and has content
            potfile_path = Path(config.potfilePath)
            if not potfile_path.exists():
                self.logger.warning(f"Potfile not found at {config.potfilePath}")
                return
            
            # Read the potfile content
            with open(potfile_path, 'r') as f:
                potfile_content = f.read().strip()
            
            if not potfile_content:
                self.logger.info("Potfile is empty, no hashes to send")
                return
            
            # Encode potfile content as base64
            potfile_content_b64 = base64.b64encode(potfile_content.encode('utf-8')).decode('utf-8')
            
            # Split content into lines
            potfile_lines = potfile_content.split('\n')
            cracked_hashes = []
            
            # Get all cracked hashes from the potfile
            for line in potfile_lines:
                if line.strip():  # Skip empty lines
                    cracked_hashes.append(line.strip())
            
            if not cracked_hashes:
                self.logger.info("No cracked hashes found in potfile")
                return
            
            # Get current recovery statistics
            total_recovered = self.last_recovered_hashes[0] if self.last_recovered_hashes else 0
            total_hashes = self.last_recovered_hashes[1] if self.last_recovered_hashes else 0
            
            self.logger.info(f"Sending {len(cracked_hashes)} cracked hashes to control server (newly recovered: {newly_recovered_count})")
            
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer + "/api/worker-logs"
            else:
                url = f"https://{config.controlServer}/api/worker-logs"

            payload = {
                "campaignId": config.campaignId,
                "instanceId": AWS_INSTANCE_ID,
                "region": AWS_REGION,
                "timestamp": datetime.now().isoformat(),
                "status": {"status": "sending_cracked_hashes"},
                "hashcatStatus": {
                    "newly_recovered_count": newly_recovered_count,
                    "total_recovered": total_recovered,
                    "total_hashes": total_hashes,
                    "cracked_hashes_content": potfile_content_b64,
                    "cracked_hashes_count": len(cracked_hashes),
                    "potfile_path": str(potfile_path),
                    "algorithm": config.hashTypeName,
                    "hash_type": config.hashType
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 201:
                        self.logger.info(f"Cracked hashes sent successfully: {len(cracked_hashes)} hashes")
                    else:
                        self.logger.warning(f"Failed to send cracked hashes: {response.status}")

        except Exception as e:
            self.logger.error(f"Error sending cracked hashes: {str(e)}")

    async def send_cracked_hashes_on_completion(self, config: CampaignConfig):
        """Send the final cracked hashes from the potfile to the control server when campaign is completed."""
        try:
            # Check if potfile exists and has content
            potfile_path = Path(config.potfilePath)
            if not potfile_path.exists():
                self.logger.warning(f"Potfile not found at {config.potfilePath}")
                return
            
            # Read the potfile content
            with open(potfile_path, 'r') as f:
                potfile_content = f.read().strip()
            
            if not potfile_content:
                self.logger.info("Potfile is empty, no hashes to send")
                return
            
            # Encode potfile content as base64
            potfile_content_b64 = base64.b64encode(potfile_content.encode('utf-8')).decode('utf-8')
            
            # Split content into lines
            potfile_lines = potfile_content.split('\n')
            cracked_hashes = []
            
            # Get all cracked hashes from the potfile
            for line in potfile_lines:
                if line.strip():  # Skip empty lines
                    cracked_hashes.append(line.strip())
            
            if not cracked_hashes:
                self.logger.info("No cracked hashes found in potfile")
                return
            
            # Get current recovery statistics
            total_recovered = self.last_recovered_hashes[0] if self.last_recovered_hashes else 0
            total_hashes = self.last_recovered_hashes[1] if self.last_recovered_hashes else 0
            
            self.logger.info(f"Sending final cracked hashes from completed campaign: {len(cracked_hashes)} hashes")
            self.logger.debug(f"Potfile content preview: {potfile_content[:200]}...")
            
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer + "/api/worker-logs"
            else:
                url = f"https://{config.controlServer}/api/worker-logs"

            payload = {
                "campaignId": config.campaignId,
                "instanceId": AWS_INSTANCE_ID,
                "region": AWS_REGION,
                "timestamp": datetime.now().isoformat(),
                "status": {"status": "completed"},
                "hashcatStatus": {
                    "total_recovered": total_recovered,
                    "total_hashes": total_hashes,
                    "cracked_hashes_content": potfile_content_b64,
                    "cracked_hashes_count": len(cracked_hashes),
                    "potfile_path": str(potfile_path),
                    "algorithm": config.hashTypeName,
                    "hash_type": config.hashType
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 201:
                        self.logger.info(f"Final cracked hashes sent successfully: {len(cracked_hashes)} hashes")
                    else:
                        self.logger.warning(f"Failed to send final cracked hashes: {response.status}")

        except Exception as e:
            self.logger.error(f"Error sending final cracked hashes: {str(e)}")

    def check_for_new_recovered_hashes(self, hashcat_status_data: Dict[str, Any]) -> int:
        """Check if there are new recovered hashes and return the count of newly recovered hashes.
        
        The recovered_hashes array from hashcat has format [recovered_count, total_count]
        where recovered_count is the number of hashes recovered so far.
        """
        current_recovered_hashes = hashcat_status_data.get("recovered_hashes", [])
        
        # Validate the format - should be [recovered_count, total_count]
        if not isinstance(current_recovered_hashes, list) or len(current_recovered_hashes) != 2:
            self.logger.warning(f"Invalid recovered_hashes format: {current_recovered_hashes}")
            return 0
        
        current_recovered_count = current_recovered_hashes[0]
        total_hashes = current_recovered_hashes[1]
        
        # Get the previous recovered count
        previous_recovered_count = self.last_recovered_hashes[0] if self.last_recovered_hashes else 0
        
        # Calculate how many new hashes were recovered
        newly_recovered = current_recovered_count - previous_recovered_count
        
        # Update the last known recovered hashes
        self.last_recovered_hashes = current_recovered_hashes.copy()
        
        # Log for debugging
        if newly_recovered > 0:
            self.logger.info(f"New hashes recovered! Previous: {previous_recovered_count}, Current: {current_recovered_count}, New: {newly_recovered}, Total: {total_hashes}")
        else:
            self.logger.debug(f"Recovered hashes status - Previous: {previous_recovered_count}, Current: {current_recovered_count}, Total: {total_hashes}")
        
        return newly_recovered
    
    def reset_recovered_hashes_tracking(self):
        """Reset the recovered hashes tracking for a new campaign."""
        self.last_recovered_hashes = [0, 0]  # [recovered_count, total_count] - start with 0 recovered
        self.logger.info("Reset recovered hashes tracking for new campaign")

# Initialize FastAPI app
app = FastAPI(
    title="Hashcat Worker Server",
    description="A professional Python server for executing hashcat processes with campaign configuration",
    version="2.0.0"
)

# Initialize worker
worker = HashcatWorker()

# Global variable to track if auto-start is requested
AUTO_START_REQUESTED = True

@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info("Hashcat Worker Server starting up...")
    logger.info(f"Working directory: {worker.work_dir}")
    logger.info(f"Download directory: {worker.download_dir}")
    
    # Fetch AWS metadata
    await fetch_aws_metadata()
    
    # Auto-start campaign if requested
    if AUTO_START_REQUESTED:
        async def auto_start_campaign():
            await asyncio.sleep(2)  # Wait for server to start
            if os.path.exists(CONFIG_FILE_PATH):
                logger.info(f"Auto-starting campaign processing from {CONFIG_FILE_PATH}")
                await worker.process_campaign(CONFIG_FILE_PATH)
            else:
                logger.error(f"Config file not found: {CONFIG_FILE_PATH}")
        
        # Schedule auto-start
        asyncio.create_task(auto_start_campaign())

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event."""
    logger.info("Hashcat Worker Server shutting down...")
    if worker.current_process:
        worker.current_process.terminate()
    if worker.status_task:
        worker.status_task.cancel()

@app.post("/hello", response_model=HelloResponse)
async def hello_endpoint(request: HelloRequest):
    """Hello endpoint for testing connectivity."""
    logger.info(f"Received hello request: {request.message}")
    
    timestamp = request.timestamp or datetime.now().isoformat()
    
    return HelloResponse(
        status="success",
        message=f"Hello! Received: {request.message}",
        timestamp=timestamp
    )

@app.get("/logs")
async def get_logs():
    """Get all log files and their contents."""
    try:
        log_dir = Path("logs")
        if not log_dir.exists():
            return JSONResponse(
                status_code=404,
                content={"error": "Logs directory not found"}
            )
        
        log_files = list(log_dir.glob("*.log"))
        if not log_files:
            return JSONResponse(
                status_code=404,
                content={"error": "No log files found"}
            )
        
        # Get the most recent log file
        latest_log = max(log_files, key=lambda x: x.stat().st_mtime)
        
        with open(latest_log, 'r') as f:
            log_content = f.read()
        
        return JSONResponse(content={
            "log_file": str(latest_log),
            "content": log_content,
            "all_log_files": [str(f) for f in log_files]
        })
        
    except Exception as e:
        logger.error(f"Error reading logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/process-campaign")
async def process_campaign():
    """Process campaign from configuration file."""
    try:
        if not os.path.exists(CONFIG_FILE_PATH):
            raise HTTPException(
                status_code=404,
                detail=f"Configuration file {CONFIG_FILE_PATH} not found"
            )
        
        logger.info(f"Processing campaign from {CONFIG_FILE_PATH}")
        result = await worker.process_campaign(CONFIG_FILE_PATH)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        logger.error(f"Error processing campaign: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/start-campaign")
async def start_campaign():
    """Start campaign processing in background."""
    try:
        if not os.path.exists(CONFIG_FILE_PATH):
            raise HTTPException(
                status_code=404,
                detail=f"Configuration file {CONFIG_FILE_PATH} not found"
            )
        
        logger.info(f"Starting campaign processing from {CONFIG_FILE_PATH}")
        
        # Start campaign processing in background
        asyncio.create_task(worker.process_campaign(CONFIG_FILE_PATH))
        
        return JSONResponse(content={
            "status": "started",
            "message": "Campaign processing started in background"
        })
        
    except Exception as e:
        logger.error(f"Error starting campaign: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Hashcat Worker Server",
        "instance_id": AWS_INSTANCE_ID,
        "region": AWS_REGION,
        "process_running": worker.current_process is not None and worker.current_process.returncode is None
    })

@app.get("/recovered-hashes")
async def get_recovered_hashes():
    """Get current recovered hashes tracking status."""
    total_recovered = worker.last_recovered_hashes[0] if worker.last_recovered_hashes else 0
    total_hashes = worker.last_recovered_hashes[1] if worker.last_recovered_hashes else 0
    
    return JSONResponse(content={
        "last_recovered_hashes": worker.last_recovered_hashes,
        "total_recovered": total_recovered,
        "total_hashes": total_hashes,
        "timestamp": datetime.now().isoformat()
    })

def main():
    """Main entry point for the server."""
    parser = argparse.ArgumentParser(description="Hashcat Worker Server")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind the server to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="Port to bind the server to (default: 4444)"
    )
    parser.add_argument(
        "--config",
        default="/home/ubuntu/campaigns/campaign-config.json",
        help="Path to campaign configuration file (default: /home/ubuntu/campaigns/campaign-config.json)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--auto-start",
        action="store_true",
        help="Automatically start campaign processing on startup"
    )
    
    args = parser.parse_args()
    
    logger.info(f"Starting Hashcat Worker Server on {args.host}:{args.port}")
    logger.info(f"Config file path: {args.config}")
    
    # Store config path globally for API endpoints
    global CONFIG_FILE_PATH
    CONFIG_FILE_PATH = args.config
    
    # Auto-start campaign if requested
    if args.auto_start:
        global AUTO_START_REQUESTED
        AUTO_START_REQUESTED = True
    
    uvicorn.run(
        "run:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )

if __name__ == "__main__":
    main()
