# Hashcat Worker Server

A professional Python server for executing hashcat processes with file downloads and comprehensive logging.

## Features

- **FastAPI-based REST API** with automatic OpenAPI documentation
- **Comprehensive logging** to both console and timestamped log files
- **File download capabilities** from URLs specified in configuration
- **Hashcat execution** with configurable parameters and flags
- **Health monitoring** and status endpoints
- **Professional error handling** and validation

## Requirements

- Python 3.8+
- Ubuntu/Debian Linux (for hashcat binary execution)
- hashcat binary installed on the system

## Installation on Ubuntu

1. **Update system and install dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip hashcat curl wget
   ```

2. **Navigate to the project directory:**
   ```bash
   cd hasher-worker-v2
   ```

3. **Install Python dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

4. **Create configuration file:**
   ```bash
   cp hashcat-process.json.example hashcat-process.json
   # Edit hashcat-process.json with your specific configuration
   ```

5. **Make startup script executable:**
   ```bash
   chmod +x start.sh
   ```

## Usage

### Starting the Server

```bash
# Start with default settings (port 4444)
python3 run.py

# Or use the startup script (recommended)
./start.sh

# Start with custom host and port
python3 run.py --host 127.0.0.1 --port 8080

# Start with auto-reload for development
python3 run.py --reload
```

### API Endpoints

#### POST /hello
Test connectivity and send messages.

**Request:**
```json
{
  "message": "Hello World",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Hello! Received: Hello World",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### GET /logs
Retrieve log files and their contents.

**Response:**
```json
{
  "log_file": "logs/hashcat_worker_20240101_120000.log",
  "content": "Log file contents...",
  "all_log_files": [
    "logs/hashcat_worker_20240101_120000.log",
    "logs/hashcat_worker_20240101_110000.log"
  ]
}
```

#### POST /process-hashcat
Process a hashcat job using the configuration file.

**Response:**
```json
{
  "status": "success",
  "config_file": "hashcat-process.json",
  "execution_result": {
    "return_code": 0,
    "stdout": "hashcat output...",
    "stderr": "",
    "command": "hashcat -m 0 -a 0 hashes.txt wordlist.txt -o cracked.txt"
  }
}
```

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "service": "Hashcat Worker Server"
}
```

### Configuration File Format

The `hashcat-process.json` file should contain:

```json
{
  "hashcat_binary": "/usr/bin/hashcat",
  "hash_file": "hashes.txt",
  "wordlist_file": "wordlist.txt",
  "rule_file": "rules.txt",
  "hash_type": "0",
  "additional_flags": [
    "--force",
    "--status",
    "--status-timer=10"
  ],
  "download_urls": [
    "https://example.com/hashes.txt",
    "https://example.com/wordlist.txt",
    "https://example.com/rules.txt"
  ],
  "output_file": "cracked.txt"
}
```

#### Configuration Fields

- **hashcat_binary**: Path to the hashcat executable
- **hash_file**: Path to the file containing hashes to crack
- **wordlist_file**: Path to the wordlist file
- **rule_file**: (Optional) Path to the rules file
- **hash_type**: Hash type identifier (e.g., "0" for MD5, "100" for SHA1)
- **additional_flags**: Array of additional hashcat command-line flags
- **download_urls**: Array of URLs to download files from
- **output_file**: Path for the output file containing cracked passwords

## Project Structure

```
hasher-worker-v2/
├── run.py                    # Main server application
├── requirements.txt          # Python dependencies
├── hashcat-process.json      # Hashcat configuration (create from example)
├── hashcat-process.json.example  # Configuration template
├── README.md                 # This file
├── logs/                     # Log files directory (auto-created)
└── work/                     # Working directory (auto-created)
    └── downloads/            # Downloaded files (auto-created)
```

## Logging

The server creates timestamped log files in the `logs/` directory. Each log file contains:
- Application startup/shutdown events
- API request logs
- Hashcat execution details
- Download progress
- Error messages and stack traces

## Error Handling

The server includes comprehensive error handling for:
- Missing configuration files
- Invalid JSON configuration
- Download failures
- Hashcat execution errors
- File system issues

## Development

### Running in Development Mode

```bash
python3 run.py --reload
```

This enables auto-reload when files change.

### API Documentation

Once the server is running, visit:
- **Swagger UI**: http://localhost:4444/docs
- **ReDoc**: http://localhost:4444/redoc

## Security Considerations

- The server binds to `0.0.0.0` by default (all interfaces)
- Use appropriate firewall rules in production
- Validate all downloaded files before processing
- Consider using HTTPS in production environments
- Implement authentication if needed for production use

## System Service (Optional)

To run the server as a system service on Ubuntu:

1. **Create systemd service file:**
   ```bash
   sudo nano /etc/systemd/system/hashcat-worker.service
   ```

2. **Add the following content:**
   ```ini
   [Unit]
   Description=Hashcat Worker Server
   After=network.target

   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/path/to/hasher-worker-v2
   ExecStart=/usr/bin/python3 /path/to/hasher-worker-v2/run.py
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable and start the service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable hashcat-worker
   sudo systemctl start hashcat-worker
   sudo systemctl status hashcat-worker
   ```

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port using `--port` argument
2. **Permission denied**: Ensure hashcat binary is executable
3. **Download failures**: Check network connectivity and URL validity
4. **Configuration errors**: Validate JSON syntax and required fields

### Debug Mode

For detailed debugging, check the log files in the `logs/` directory.

## License

This project is provided as-is for educational and development purposes. 