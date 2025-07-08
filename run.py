#!/usr/bin/env python3
"""
Hashcat Worker Server
A Python server for executing hashcat processes with campaign configuration and status reporting.
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
        
    async def send_status_to_control_server(self, config: CampaignConfig, status_data: Dict[str, Any]):
        """Send status update to the control server."""
        try:
            # Handle webhook URLs properly
            if config.controlServer.startswith('https://'):
                url = config.controlServer
            else:
                url = f"http://{config.controlServer}:{config.controlPort}/status"
            
            payload = {
                "campaignId": config.campaignId,
                "timestamp": datetime.now().isoformat(),
                "status": status_data
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info(f"Status sent to control server: {status_data.get('status', 'unknown')}")
                    else:
                        self.logger.warning(f"Failed to send status to control server: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error sending status to control server: {str(e)}")

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
    
    async def monitor_hashcat_process(self, config: CampaignConfig, process: asyncio.subprocess.Process):
        """Monitor hashcat process and send status updates."""
        try:
            while process.returncode is None:
                # Read status from hashcat's JSON output
                if process.stdout:
                    try:
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                        if line:
                            status_line = line.decode('utf-8').strip()
                            if status_line.startswith('{"status"'):
                                try:
                                    status_data = json.loads(status_line)
                                    await self.send_status_to_control_server(config, status_data)
                                except json.JSONDecodeError:
                                    self.logger.warning(f"Invalid JSON status line: {status_line}")
                    except asyncio.TimeoutError:
                        continue
                
                await asyncio.sleep(config.statusTimer)
            
            # Send final status
            final_status = {
                "status": "completed" if process.returncode == 0 else "failed",
                "return_code": process.returncode
            }
            await self.send_status_to_control_server(config, final_status)
            
        except Exception as e:
            self.logger.error(f"Error monitoring hashcat process: {str(e)}")
    
    async def execute_hashcat(self, config: CampaignConfig, downloaded_files: Dict[str, str]) -> Dict[str, Any]:
        """Execute hashcat with the campaign configuration."""
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
            
            # Start monitoring task
            self.status_task = asyncio.create_task(
                self.monitor_hashcat_process(config, self.current_process)
            )
            
            # Wait for process to complete
            stdout, stderr = await self.current_process.communicate()
            
            # Cancel monitoring task
            if self.status_task:
                self.status_task.cancel()
                try:
                    await self.status_task
                except asyncio.CancelledError:
                    pass
            
            result = {
                'return_code': self.current_process.returncode,
                'stdout': stdout.decode('utf-8') if stdout else '',
                'stderr': stderr.decode('utf-8') if stderr else '',
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

# Initialize FastAPI app
app = FastAPI(
    title="Hashcat Worker Server",
    description="A professional Python server for executing hashcat processes with campaign configuration",
    version="2.0.0"
)

# Initialize worker
worker = HashcatWorker()

@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info("Hashcat Worker Server starting up...")
    logger.info(f"Working directory: {worker.work_dir}")
    logger.info(f"Download directory: {worker.download_dir}")

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
        config_file = "campaign-config.json"
        if not os.path.exists(config_file):
            raise HTTPException(
                status_code=404,
                detail=f"Configuration file {config_file} not found"
            )
        
        logger.info(f"Processing campaign from {config_file}")
        result = await worker.process_campaign(config_file)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        logger.error(f"Error processing campaign: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/start-campaign")
async def start_campaign():
    """Start campaign processing in background."""
    try:
        config_file = "campaign-config.json"
        if not os.path.exists(config_file):
            raise HTTPException(
                status_code=404,
                detail=f"Configuration file {config_file} not found"
            )
        
        logger.info(f"Starting campaign processing from {config_file}")
        
        # Start campaign processing in background
        asyncio.create_task(worker.process_campaign(config_file))
        
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
        "process_running": worker.current_process is not None and worker.current_process.returncode is None
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
    
    # Auto-start campaign if requested
    if args.auto_start:
        async def auto_start_campaign():
            await asyncio.sleep(2)  # Wait for server to start
            config_file = "campaign-config.json"
            if os.path.exists(config_file):
                logger.info("Auto-starting campaign processing...")
                await worker.process_campaign(config_file)
        
        # Schedule auto-start
        asyncio.create_task(auto_start_campaign())
    
    uvicorn.run(
        "run:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )

if __name__ == "__main__":
    main()
