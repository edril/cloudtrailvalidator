# CloudTrail Log Validator

A Python tool for validating AWS CloudTrail logs using corpus-based analysis to detect synthetic or invalid log entries.

## Overview

CloudTrail Log Validator builds a reference corpus from genuine AWS CloudTrail logs and uses it to validate test logs. It detects anomalies by identifying field paths that never appear in real CloudTrail events, making it effective at spotting synthetic or tampered logs.

The reference corpus data derives from the excellent [flaws.cloud](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/) public CloudTrail dataset by Summit Route.

## Features

- **Corpus Building**: Extract field paths from real CloudTrail logs to build a reference database
- **Structure Validation**: Verify mandatory CloudTrail fields and data types
- **Corpus Validation**: Detect unknown field paths that don't exist in genuine logs
- **Batch Processing**: Recursively process directories of JSON and gzipped JSON files
- **Detailed Reporting**: Console output with optional CSV export

## Installation

```bash
git clone https://github.com/yourusername/cloudtrailvalidator.git
cd cloudtrailvalidator
```

No external dependencies required - uses Python standard library only.

## Usage

### 1. Build Reference Corpus

First, build a corpus from your real CloudTrail logs:

```bash
python validator.py --build /path/to/real/cloudtrail/logs/
```

This will:
- Recursively scan the directory for `*.json` and `*.json.gz` files
- Extract all field paths from CloudTrail events
- Save the corpus to `corpus.db`

### 2. Validate Test Logs

Validate suspicious logs against the corpus:

```bash
python validator.py test_log.json
```

Add `--csv` flag to export results to CSV:

```bash
python validator.py test_log.json --csv
```

## How It Works

### Corpus Building
1. Scans directories for CloudTrail log files
2. Extracts all nested field paths (e.g., `userIdentity.type`, `requestParameters.bucketName`)
3. Builds a reference database of legitimate field paths
4. Stores statistics about event types and counts

### Validation
1. **Structure Check**: Verifies mandatory fields (`eventVersion`, `eventTime`, `eventSource`, `eventName`, `awsRegion`, `userIdentity`)
2. **Corpus Check**: Compares event field paths against the reference corpus
3. **Anomaly Detection**: Flags any field paths not seen in real logs

## Example Output

```
🔍 Validating: suspicious_log.json
📊 Found 2 event(s) to validate

Event 0: ✅ PASS (s3.amazonaws.com.ListBuckets)
Event 1: ❌ FAIL (ec2.amazonaws.com.RunInstances)
  ❌ CORPUS: 3 field path(s) never seen in 15000 real events:
     • customField
     • requestParameters.fakeParameter
     • userIdentity.invalidType

============================================================
📊 SUMMARY: 1 PASS, 1 FAIL (total: 2)
============================================================
⚠️  1 event(s) failed validation - likely synthetic/invalid
```

## Use Cases

- **Security Analysis**: Detect forged or modified CloudTrail logs
- **Log Validation**: Verify integrity of CloudTrail data
- **Threat Detection**: Identify suspicious log entries with unusual fields
- **Compliance**: Ensure CloudTrail logs match expected AWS schema

## File Structure

```
cloudtrailvalidator/
├── validator.py          # Main validation script
├── corpus.db            # Reference corpus (generated)
├── validation_report.csv # Validation results (optional)
└── README.md
```

## Requirements

- Python 3.6+
- No external dependencies

## License

MIT

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.
