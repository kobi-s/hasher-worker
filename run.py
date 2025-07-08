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

# Global variable to store AWS instance ID
AWS_INSTANCE_ID = None

async def fetch_aws_instance_id():
    """Fetch AWS instance ID from metadata service."""
    global AWS_INSTANCE_ID
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://169.254.169.254/latest/meta-data/instance-id') as response:
                if response.status == 200:
                    AWS_INSTANCE_ID = await response.text()
                    logger.info(f"Fetched AWS instance ID: {AWS_INSTANCE_ID}")
                    return AWS_INSTANCE_ID
                else:
                    logger.warning(f"Failed to fetch AWS instance ID: {response.status}")
                    AWS_INSTANCE_ID = "unknown"
                    return AWS_INSTANCE_ID
    except Exception as e:
        logger.warning(f"Error fetching AWS instance ID: {str(e)}")
        AWS_INSTANCE_ID = "unknown"
        return AWS_INSTANCE_ID

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
    wordlist: str
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
            else:
                # Fallback to the wordlist URL if no wordlistFiles are provided
                wordlist_filename = f"wordlist_{config.campaignId}.txt"
                wordlist_path = await self.download_file(config.wordlist, wordlist_filename)
                downloaded_files['wordlist_file'] = wordlist_path
            
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
                "timestamp": datetime.now().isoformat(),
                "status": status_data  # This is always the instance status (e.g., 'running', 'completed', etc.)
            }
            if hashcat_status is not None:
                payload["hashcatStatus"] = hashcat_status

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
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
                "timestamp": datetime.now().isoformat(),
                "status": {"status": "running"},  # Always use instance status
                "hashcatStatus": progress_data  # Hashcat progress data
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
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
                                new_recovered_hashes = self.check_for_new_recovered_hashes(hashcat_status_data)
                                
                                # Send regular status update
                                await self.send_status_to_control_server(
                                    config,
                                    {"status": "running"},  # Always use instance status here
                                    hashcat_status=hashcat_status_data
                                )
                                await self.send_progress_to_control_server(config, hashcat_status_data)
                                
                                # Send hash recovery notification if new hashes were found
                                if new_recovered_hashes:
                                    await self.send_hash_recovery_notification(config, new_recovered_hashes)
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
            
            # Send final status
            final_status = {
                "status": "completed" if self.current_process.returncode == 0 else "failed",
                "return_code": self.current_process.returncode
            }
            await self.send_status_to_control_server(config, final_status)
            
            result = {
                'return_code': self.current_process.returncode,
                'stdout': '\n'.join(stdout_lines),
                'stderr': '\n'.join(stderr_lines),
                'command': ' '.join(cmd)
            }
            
            if self.current_process.returncode == 0:
                self.logger.info("Hashcat execution completed successfully")
            else:
                self.logger.warning(f"Hashcat execution completed with return code {self.current_process.returncode}")
            
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

    async def send_hash_recovery_notification(self, config: CampaignConfig, recovered_hashes: List[int]):
        """Send notification to control server about newly recovered hashes."""
        try:
            self.logger.info(f"New hashes recovered! Hash indices: {recovered_hashes}")
            
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer + "/api/worker-logs"
            else:
                url = f"https://{config.controlServer}/api/worker-logs"

            payload = {
                "campaignId": config.campaignId,
                "instanceId": AWS_INSTANCE_ID,
                "timestamp": datetime.now().isoformat(),
                "status": {"status": "hash_recovered"},  # Special status for hash recovery
                "hashcatStatus": {
                    "recovered_hashes": recovered_hashes
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info(f"Hash recovery notification sent successfully: {len(recovered_hashes)} hashes recovered")
                    else:
                        self.logger.warning(f"Failed to send hash recovery notification: {response.status}")

        except Exception as e:
            self.logger.error(f"Error sending hash recovery notification: {str(e)}")

    def check_for_new_recovered_hashes(self, hashcat_status_data: Dict[str, Any]) -> List[int]:
        """Check if there are new recovered hashes and return the new ones."""
        current_recovered_hashes = hashcat_status_data.get("recovered_hashes", [])
        
        # Find new hashes that weren't in the previous status
        new_hashes = []
        for hash_index in current_recovered_hashes:
            if hash_index not in self.last_recovered_hashes:
                new_hashes.append(hash_index)
        
        # Update the last known recovered hashes
        self.last_recovered_hashes = current_recovered_hashes.copy()
        
        # Log for debugging (only if there are recovered hashes)
        if current_recovered_hashes:
            self.logger.debug(f"Current recovered hashes: {current_recovered_hashes}, New hashes: {new_hashes}")
        
        return new_hashes
    
    def reset_recovered_hashes_tracking(self):
        """Reset the recovered hashes tracking for a new campaign."""
        self.last_recovered_hashes = []
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
    
    # Fetch AWS instance ID
    await fetch_aws_instance_id()
    
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
        "process_running": worker.current_process is not None and worker.current_process.returncode is None
    })

@app.get("/recovered-hashes")
async def get_recovered_hashes():
    """Get current recovered hashes tracking status."""
    return JSONResponse(content={
        "last_recovered_hashes": worker.last_recovered_hashes,
        "total_recovered": len(worker.last_recovered_hashes),
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
