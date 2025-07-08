# Hashcat Worker Server v2.0

A professional Python server for executing hashcat processes with campaign configuration and real-time status reporting.

## Features

- **Campaign-based Configuration**: Uses JSON configuration files to define hashcat campaigns
- **Automatic File Downloads**: Downloads hash files, wordlists, and rule files from URLs
- **Real-time Status Reporting**: Sends JSON status updates to control server during execution
- **Multiple Attack Modes**: Supports straight, combination, brute-force, and hybrid attacks
- **JSON Output**: Uses hashcat's `--status-json` for structured status reporting
- **Background Processing**: Can run campaigns in background with auto-start capability

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure hashcat is installed and available in PATH:
```bash
hashcat --version
```

## Configuration


### Start the server:

```bash
# Basic start
python run.py

# With custom host/port
python run.py --host 0.0.0.0 --port 4444

# With auto-reload for development
python run.py --reload

# Auto-start campaign processing on startup
python run.py --auto-start
```

### API Endpoints

- `POST /hello` - Test connectivity
- `GET /logs` - Get log files
- `POST /process-campaign` - Process campaign synchronously
- `POST /start-campaign` - Start campaign processing in background
- `GET /health` - Health check

### Processing a Campaign

1. **Place your `campaign-config.json` file in the worker directory**

2. **Start the campaign processing:**
   ```bash
   curl -X POST http://localhost:4444/process-campaign
   ```

3. **Or start in background:**
   ```bash
   curl -X POST http://localhost:4444/start-campaign
   ```

## Attack Modes Supported

- **Mode 0**: Straight attack (wordlist)
- **Mode 1**: Combination attack (two wordlists)
- **Mode 3**: Brute-force attack (mask)
- **Mode 6**: Hybrid attack (wordlist + mask)
- **Mode 7**: Hybrid attack (mask + wordlist)

## Status Reporting

The worker automatically sends status updates to the control server at the specified interval. Status updates include:

- Campaign start/completion
- File download progress
- Hashcat execution status
- Real-time progress from hashcat's JSON output

## File Structure

```
hasher-worker-v2/
├── run.py                 # Main server script
├── campaign-config.json   # Campaign configuration
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── work/                 # Working directory (created automatically)
│   └── downloads/        # Downloaded files
└── logs/                 # Log files (created automatically)
```

## Logging

Logs are automatically created in the `logs/` directory with timestamps. You can view logs via the API:

```bash
curl http://localhost:4444/logs
```

## Control Server Integration

The worker sends status updates to the control server at `http://{controlServer}:{controlPort}/status` with the following payload:

```json
{
  "campaignId": "campaign-id",
  "timestamp": "2024-01-01T12:00:00Z",
  "status": {
    "status": "running",
    "progress": 25.5,
    "speed": 1000000,
    "eta": 3600
  }
}
```

## Error Handling

- Automatic retry for file downloads
- Graceful handling of hashcat process termination
- Detailed error logging
- Status reporting for failures

## Development

For development, use the `--reload` flag to enable auto-reload:

```bash
python run.py --reload --host 0.0.0.0 --port 4444
```

## Troubleshooting

1. **Hashcat not found**: Ensure hashcat is installed and in PATH
2. **Download failures**: Check network connectivity and URL accessibility
3. **Control server unreachable**: Verify control server is running and accessible
4. **Permission errors**: Ensure write permissions for work/ and logs/ directories

## License

This project is provided as-is for educational and development purposes. 