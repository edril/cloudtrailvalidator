# CloudTrail Log Validator

A Python tool for validating AWS CloudTrail logs using corpus-based analysis to detect synthetic or invalid log entries.

## Overview

CloudTrail Log Validator builds a reference corpus from genuine AWS CloudTrail logs and uses it to validate test logs. It detects anomalies by identifying field paths that never appear in real CloudTrail events, making it effective at spotting synthetic or tampered logs.

The reference corpus data derives from the excellent [flaws.cloud](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/) public CloudTrail dataset by Summit Route.

## Features

- **Corpus Building**: Extract field paths from real CloudTrail logs to build a reference database
- **Incremental Updates**: Append new logs to existing corpus without rebuilding
- **Multi-Format Support**: Handles standard CloudTrail JSON, JSON arrays, and NDJSON (Splunk format)
- **Structure Validation**: Verify mandatory CloudTrail fields and data types
- **Corpus Validation**: Detect unknown field paths that don't exist in genuine logs
- **Batch Processing**: Recursively process directories of JSON and gzipped JSON files
- **Batch Validation Mode**: Quick PASS/FAIL triage across multiple test files
- **Detailed Reporting**: Console output with optional CSV export

## Installation

```bash
git clone https://github.com/yourusername/cloudtrailvalidator.git
cd cloudtrailvalidator
```

No external dependencies required - uses Python standard library only.

## Usage

### Version 2: Individual File Validation

**1. Build Reference Corpus**

First, build a corpus from your real CloudTrail logs:

```bash
python validator_v2.py --build /path/to/real/cloudtrail/logs/
```

This will:
- Recursively scan the directory for `*.json` and `*.json.gz` files
- Extract all field paths from CloudTrail events
- Save the corpus to `corpus.db`

**2. Append More Logs (Optional)**

Add new logs to existing corpus without rebuilding:

```bash
python validator_v2.py --append /path/to/more/cloudtrail/logs/
```

This merges new data into `corpus.db` and shows incremental statistics.

**3. Validate Test Logs**

Validate suspicious logs against the corpus:

```bash
python validator_v2.py test_log.json
```

Add `--csv` flag to export results to CSV:

```bash
python validator_v2.py test_log.json --csv
```

### Version 3: Batch Validation Mode

**Batch validate multiple files** for quick triage:

```bash
python validator_v3.py --batch /path/to/test/logs/
```

Output shows simple PASS/FAIL per file:
```
✅ PASS - legitimate_log.json
✅ PASS - another_good_log.json
❌ FAIL - suspicious_log.json
❌ FAIL - synthetic_log.json

📊 BATCH SUMMARY: 2 PASS, 2 FAIL (total: 4)

⚠️  Failed files (validate individually for details):
   • suspicious_log.json
   • synthetic_log.json
```

Then validate failed files individually for detailed analysis:

```bash
python validator_v3.py suspicious_log.json
```

V3 also supports `--build`, `--append`, and single file validation like V2.

## Analyzing the Corpus

View corpus statistics using `jq` (if installed):

```bash
# View summary stats
jq '.stats' corpus.db

# Count total field paths
jq '.field_paths | length' corpus.db

# View first 20 field paths
jq '.field_paths[:20]' corpus.db

# Search for specific field paths
jq '.field_paths[] | select(contains("userIdentity"))' corpus.db

# Top 10 event types
jq '.stats.event_types | to_entries | sort_by(.value) | reverse | .[0:10]' corpus.db
```

Without `jq`:

```bash
# Basic view
python3 -m json.tool corpus.db | less

# Quick stats
python3 -c "import json; d=json.load(open('corpus.db')); print(f'Paths: {len(d[\"field_paths\"])}, Events: {d[\"stats\"][\"event_count\"]}')"
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
- **Red Team Testing**: Validate synthetic attack logs appear realistic
- **Compliance**: Ensure CloudTrail logs match expected AWS schema

## File Structure

```
cloudtrailvalidator/
├── validator_v2.py       # Individual file validation
├── validator_v3.py       # Batch validation mode
├── corpus.db            # Reference corpus (generated)
├── validation_report.csv # Validation results (optional)
├── batch_validation_report.csv # Batch results (v3)
├── README.md
└── TECHNICAL_DESIGN.md  # Technical documentation
```

## Requirements

- Python 3.6+
- No external dependencies

## Documentation

- **README.md** (this file): User guide and quick start
- **TECHNICAL_DESIGN.md**: Architecture, design decisions, limitations, and security analysis


