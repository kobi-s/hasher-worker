#!/usr/bin/env python3
"""
Hashcat Worker Server
A Python server for executing hashcat processes with file downloads and logging.
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

# Pydantic models for request/response
class HelloRequest(BaseModel):
    message: str
    timestamp: Optional[str] = None

class HelloResponse(BaseModel):
    status: str
    message: str
    timestamp: str

class HashcatProcess(BaseModel):
    hashcat_binary: str
    hash_file: str
    wordlist_file: str
    rule_file: Optional[str] = None
    hash_type: str
    additional_flags: List[str] = []
    download_urls: List[str] = []
    output_file: str

@dataclass
class HashcatConfig:
    """Configuration for hashcat execution."""
    binary_path: str
    hash_file: str
    wordlist_file: str
    hash_type: str
    output_file: str
    rule_file: Optional[str] = None
    additional_flags: List[str] = None

class HashcatWorker:
    """Main worker class for handling hashcat operations."""
    
    def __init__(self, work_dir: str = "work"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)
        self.download_dir = self.work_dir / "downloads"
        self.download_dir.mkdir(exist_ok=True)
        self.logger = logger
        
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
    
    async def download_files(self, urls: List[str]) -> List[str]:
        """Download multiple files from URLs."""
        downloaded_files = []
        for url in urls:
            filename = url.split('/')[-1]
            file_path = await self.download_file(url, filename)
            downloaded_files.append(file_path)
        return downloaded_files
    
    def read_hashcat_config(self, config_file: str) -> HashcatConfig:
        """Read and parse hashcat process configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            self.logger.info(f"Loaded hashcat configuration from {config_file}")
            
            # Validate required fields
            required_fields = ['hashcat_binary', 'hash_file', 'wordlist_file', 'hash_type', 'output_file']
            for field in required_fields:
                if field not in config_data:
                    raise ValueError(f"Missing required field: {field}")
            
            return HashcatConfig(
                binary_path=config_data['hashcat_binary'],
                hash_file=config_data['hash_file'],
                wordlist_file=config_data['wordlist_file'],
                hash_type=config_data['hash_type'],
                output_file=config_data['output_file'],
                rule_file=config_data.get('rule_file'),
                additional_flags=config_data.get('additional_flags', [])
            )
        except Exception as e:
            self.logger.error(f"Error reading hashcat config: {str(e)}")
            raise
    
    async def execute_hashcat(self, config: HashcatConfig) -> Dict[str, Any]:
        """Execute hashcat with the given configuration."""
        try:
            # Build hashcat command
            cmd = [config.binary_path, '-m', config.hash_type]
            
            # Add hash file
            cmd.extend(['-a', '0', config.hash_file, config.wordlist_file])
            
            # Add rule file if specified
            if config.rule_file:
                cmd.extend(['-r', config.rule_file])
            
            # Add additional flags
            if config.additional_flags:
                cmd.extend(config.additional_flags)
            
            # Add output file
            cmd.extend(['-o', config.output_file])
            
            self.logger.info(f"Executing hashcat command: {' '.join(cmd)}")
            
            # Execute hashcat
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                'return_code': process.returncode,
                'stdout': stdout.decode('utf-8') if stdout else '',
                'stderr': stderr.decode('utf-8') if stderr else '',
                'command': ' '.join(cmd)
            }
            
            if process.returncode == 0:
                self.logger.info("Hashcat execution completed successfully")
            else:
                self.logger.warning(f"Hashcat execution completed with return code {process.returncode}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing hashcat: {str(e)}")
            raise
    
    async def process_hashcat_job(self, config_file: str) -> Dict[str, Any]:
        """Process a complete hashcat job including downloads and execution."""
        try:
            # Read configuration
            config = self.read_hashcat_config(config_file)
            
            # Download files if URLs are provided
            if hasattr(config, 'download_urls') and config.download_urls:
                await self.download_files(config.download_urls)
            
            # Execute hashcat
            result = await self.execute_hashcat(config)
            
            return {
                'status': 'success',
                'config_file': config_file,
                'execution_result': result
            }
            
        except Exception as e:
            self.logger.error(f"Error processing hashcat job: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'config_file': config_file
            }

# Initialize FastAPI app
app = FastAPI(
    title="Hashcat Worker Server",
    description="A professional Python server for executing hashcat processes",
    version="1.0.0"
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

@app.post("/process-hashcat")
async def process_hashcat():
    """Process hashcat job from configuration file."""
    try:
        config_file = "hashcat-process.json"
        if not os.path.exists(config_file):
            raise HTTPException(
                status_code=404,
                detail=f"Configuration file {config_file} not found"
            )
        
        logger.info(f"Processing hashcat job from {config_file}")
        result = await worker.process_hashcat_job(config_file)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        logger.error(f"Error processing hashcat: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Hashcat Worker Server"
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
    
    args = parser.parse_args()
    
    logger.info(f"Starting Hashcat Worker Server on {args.host}:{args.port}")
    
    uvicorn.run(
        "run:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )

if __name__ == "__main__":
    main()
