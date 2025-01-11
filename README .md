# Enhanced Note-Making Tool for SOC Analysis

This script automates the creation of investigation notes by extracting metadata, performing OSINT analysis using VirusTotal, IBM X-Force, and AlienVault, and summarizing findings with AI. It simplifies SOC (Security Operations Center) workflows by integrating threat intelligence and AI-powered insights.

## Features

- **Metadata Parsing**: Extracts detailed file metadata from raw text using regex.
- **OSINT Integration**:
  - **VirusTotal**: Retrieves detection counts and analysis.
  - **IBM X-Force**: Provides risk and malware family data.
  - **AlienVault**: Fetches pulse information for IOCs.
- **AI-Powered Analysis**: Summarizes OSINT findings using Gemini AI for actionable insights.
- **Investigation Notes**: Generates formatted reports with extracted metadata, analysis results, and recommended actions.

## Requirements

- Python 3.8 or higher
- Internet access for API requests
- Installed Python packages:
  - `requests`
  - `urllib3`

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/soc-analysis-tool.git
   cd soc-analysis-tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables with your API keys:
   - `VIRUSTOTAL_API_KEY`
   - `XFORCE_API_KEY`
   - `XFORCE_API_SECRET`
   - `ALIENVAULT_API_KEY`
   - `AI_API_KEY`

4. Run the script:
   ```bash
   python soc_analysis_tool.py
   ```

## Usage

1. Provide the raw text containing file details in the `raw_data` variable.
2. The script will parse the metadata, fetch OSINT analysis results, and use AI to generate a comprehensive investigation note.
3. The formatted note will include:
   - Extracted metadata
   - OSINT analysis (VirusTotal, IBM X-Force, AlienVault)
   - AI-generated insights
   - Suggested actions

## Example Output

```
### Investigation Note

#### Extracted Metadata:
- File Name: report2023_update.docx
- File Path: C:\Temp\Downloads\report2023_update.docx
- Detection Type: Malicious
- Initiated By: User action
- Engine: Custom Engine
- Classification: Malware
- SHA1 Hash: a1b2c3d4e5f67890abcdef1234567890abcdef12
- Originating Process: word.exe
- Computer Name: User-PC
- OS Version: Windows 10
- Logged In User: JohnDoe
- IP Address: 192.168.0.1
- Full Disk Scan: Completed
- Signature Verification: Valid

#### OSINT Analysis:
- VirusTotal: 5/10 detections
- IBM X-Force: Risk: High, Family: Trojans
- AlienVault: Found in 3 pulses

#### AI Analysis:
The file exhibits suspicious behavior and poses security risks. Analysts should investigate its origin and consider quarantining it.

#### Suggested Actions:
- Quarantine the file if it is suspicious.
- Investigate the origin and usage.
- Follow organizational response protocols.
```
