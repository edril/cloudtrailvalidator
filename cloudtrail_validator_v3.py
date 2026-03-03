#!/usr/bin/env python3
"""
CloudTrail Log Validator - Corpus-based validation for synthetic log detection

Four modes:
1. BUILD: Build reference corpus from real CloudTrail logs
   python cloudtrail_validator_v3.py --build /path/to/real/logs/

2. APPEND: Add more logs to existing corpus
   python cloudtrail_validator_v3.py --append /path/to/more/logs/

3. VALIDATE: Validate single test log against corpus
   python cloudtrail_validator_v3.py test.json [--csv]

4. BATCH: Validate multiple test logs in a directory
   python cloudtrail_validator_v3.py --batch /path/to/test/logs/
"""

import sys
import json
import gzip
from pathlib import Path
from typing import Dict, Any, List, Set
from collections import defaultdict

CORPUS_DB = Path("./corpus.db")

# Core mandatory fields for CloudTrail structure validation
CORE_MANDATORY = {
    'eventVersion',
    'eventTime', 
    'eventSource',
    'eventName',
    'awsRegion',
    'userIdentity'
}

def extract_field_paths(obj: Any, prefix: str = '') -> Set[str]:
    """
    Recursively extract all field paths from a nested structure.
    
    Examples:
      {'a': 1, 'b': {'c': 2}} -> {'a', 'b', 'b.c'}
      {'x': [{'y': 1}]} -> {'x', 'x.y'}
    """
    paths = set()
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{prefix}.{key}" if prefix else key
            paths.add(current_path)
            # Recurse into nested structures
            paths.update(extract_field_paths(value, current_path))
    
    elif isinstance(obj, list):
        # For arrays, extract paths from all items
        for item in obj:
            paths.update(extract_field_paths(item, prefix))
    
    return paths

def load_json_file(filepath: Path) -> List[Dict]:
    """Load JSON or gzipped JSON file, return list of events. Supports standard JSON and NDJSON."""
    try:
        if filepath.suffix == '.gz':
            with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                content = f.read()
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        
        # Try parsing as standard JSON first
        try:
            data = json.loads(content)
            
            # Extract Records array or treat as single event list
            if isinstance(data, dict) and 'Records' in data:
                return data['Records']
            elif isinstance(data, list):
                return data
            else:
                return [data]
        
        except json.JSONDecodeError:
            # If standard JSON fails, try NDJSON (newline-delimited JSON)
            events = []
            for line in content.strip().split('\n'):
                if line.strip():
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError as e:
                        print(f"⚠️  Skipping invalid JSON line: {e}")
            
            if events:
                return events
            else:
                raise ValueError("No valid JSON found in file")
    
    except Exception as e:
        print(f"⚠️  Error loading {filepath}: {e}")
        return []

def build_corpus(logs_dir: Path, existing_corpus: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Build or append to corpus database from real CloudTrail logs.
    
    Scans directory recursively for *.json and *.json.gz files,
    extracts all field paths, and stores statistics.
    
    If existing_corpus is provided, merges new data into it.
    """
    print(f"📂 Scanning {logs_dir} for CloudTrail logs...")
    
    # Start with existing corpus or create new
    if existing_corpus:
        all_field_paths = set(existing_corpus['field_paths'])
        event_count = existing_corpus['stats']['event_count']
        file_count = existing_corpus['stats']['file_count']
        event_types = defaultdict(int, existing_corpus['stats']['event_types'])
        print(f"📚 Appending to existing corpus: {len(all_field_paths)} field paths, {event_count} events")
    else:
        all_field_paths = set()
        event_count = 0
        file_count = 0
        event_types = defaultdict(int)
    
    # Find all JSON files recursively
    json_files = list(logs_dir.rglob("*.json"))
    json_gz_files = list(logs_dir.rglob("*.json.gz"))
    all_files = json_files + json_gz_files
    
    print(f"📊 Found {len(all_files)} log files ({len(json_files)} .json, {len(json_gz_files)} .json.gz)")
    
    new_files = 0
    new_events = 0
    new_fields = 0
    initial_field_count = len(all_field_paths)
    
    for filepath in all_files:
        events = load_json_file(filepath)
        if not events:
            continue
        
        file_count += 1
        new_files += 1
        
        for event in events:
            if not isinstance(event, dict):
                continue
            
            event_count += 1
            new_events += 1
            
            # Track event types
            event_type = f"{event.get('eventSource', 'unknown')}.{event.get('eventName', 'unknown')}"
            event_types[event_type] += 1
            
            # Extract all field paths from this event
            paths = extract_field_paths(event)
            all_field_paths.update(paths)
        
        # Progress indicator every 100 files
        if new_files % 100 == 0:
            print(f"  Processed {new_files} files, {new_events} events, {len(all_field_paths)} unique field paths...")
    
    new_fields = len(all_field_paths) - initial_field_count
    
    print(f"\n✅ Corpus {'build' if not existing_corpus else 'append'} complete:")
    print(f"   Files processed: {file_count} total ({new_files} new)")
    print(f"   Events processed: {event_count} total ({new_events} new)")
    print(f"   Unique field paths: {len(all_field_paths)} total ({new_fields} new)")
    print(f"   Event types: {len(event_types)}")
    
    # Build corpus database
    corpus = {
        'field_paths': sorted(list(all_field_paths)),
        'stats': {
            'file_count': file_count,
            'event_count': event_count,
            'event_types': dict(event_types)
        }
    }
    
    return corpus

def save_corpus(corpus: Dict[str, Any]):
    """Save corpus database to disk."""
    with open(CORPUS_DB, 'w') as f:
        json.dump(corpus, f, indent=2)
    print(f"\n💾 Corpus saved to {CORPUS_DB}")
    print(f"   Size: {CORPUS_DB.stat().st_size / 1024:.1f} KB")

def load_corpus() -> Dict[str, Any]:
    """Load corpus database from disk."""
    if not CORPUS_DB.exists():
        print(f"❌ Corpus database not found: {CORPUS_DB}")
        print(f"   Run: python {sys.argv[0]} --build /path/to/logs/")
        sys.exit(1)
    
    with open(CORPUS_DB, 'r') as f:
        corpus = json.load(f)
    
    print(f"📚 Loaded corpus: {len(corpus['field_paths'])} field paths from {corpus['stats']['event_count']} events")
    return corpus

def validate_structure(event: Dict[str, Any]) -> List[str]:
    """
    Validate core CloudTrail structure.
    
    Returns list of issues (empty if valid).
    """
    issues = []
    
    # Check mandatory fields
    for field in CORE_MANDATORY:
        if field not in event:
            issues.append(f"❌ STRUCTURE: Missing mandatory field '{field}'")
    
    # Basic type checks for critical fields
    if 'eventTime' in event and not isinstance(event['eventTime'], str):
        issues.append(f"❌ STRUCTURE: 'eventTime' must be string, got {type(event['eventTime']).__name__}")
    
    if 'userIdentity' in event and not isinstance(event['userIdentity'], dict):
        issues.append(f"❌ STRUCTURE: 'userIdentity' must be object, got {type(event['userIdentity']).__name__}")
    
    return issues

def validate_corpus(event: Dict[str, Any], corpus: Dict[str, Any]) -> List[str]:
    """
    Validate event against corpus - check if all field paths exist in real logs.
    
    Returns list of issues (empty if valid).
    """
    issues = []
    
    corpus_paths = set(corpus['field_paths'])
    event_paths = extract_field_paths(event)
    
    # Find unknown paths (not in corpus)
    unknown_paths = event_paths - corpus_paths
    
    if unknown_paths:
        issues.append(f"❌ CORPUS: {len(unknown_paths)} field path(s) never seen in {corpus['stats']['event_count']} real events:")
        for path in sorted(unknown_paths):
            issues.append(f"     • {path}")
    
    return issues

def validate_event(event: Dict[str, Any], corpus: Dict[str, Any]) -> tuple[str, List[str]]:
    """
    Validate a single event.
    
    Returns (status, issues) where status is 'PASS' or 'FAIL'.
    """
    issues = []
    
    # Step 1: Structure validation (mandatory)
    structure_issues = validate_structure(event)
    issues.extend(structure_issues)
    
    # Step 2: Corpus validation (strict)
    corpus_issues = validate_corpus(event, corpus)
    issues.extend(corpus_issues)
    
    status = 'PASS' if not issues else 'FAIL'
    return status, issues

def validate_file(filepath: Path, corpus: Dict[str, Any], csv_output: bool = False):
    """Validate a log file against corpus."""
    
    print(f"\n🔍 Validating: {filepath}")
    
    events = load_json_file(filepath)
    
    if not events:
        print("❌ No events found in file")
        return
    
    print(f"📊 Found {len(events)} event(s) to validate\n")
    
    # Validate each event
    report = []
    pass_count = 0
    fail_count = 0
    
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            print(f"Event {i}: ⚠️  SKIP (not a dict)")
            continue
        
        status, issues = validate_event(event, corpus)
        
        event_type = f"{event.get('eventSource', '?')}.{event.get('eventName', '?')}"
        
        if status == 'PASS':
            pass_count += 1
            print(f"Event {i}: ✅ PASS ({event_type})")
        else:
            fail_count += 1
            print(f"Event {i}: ❌ FAIL ({event_type})")
            for issue in issues:
                print(f"  {issue}")
        
        report.append({
            'index': i,
            'eventType': event_type,
            'status': status,
            'issueCount': len(issues)
        })
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 SUMMARY: {pass_count} PASS, {fail_count} FAIL (total: {len(events)})")
    print(f"{'='*60}")
    
    if fail_count > 0:
        print(f"⚠️  {fail_count} event(s) failed validation - likely synthetic/invalid")
    else:
        print(f"✅ All events passed - logs appear genuine")
    
    # CSV output
    if csv_output:
        import csv
        csv_path = Path('validation_report.csv')
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['index', 'eventType', 'status', 'issueCount'])
            writer.writeheader()
            writer.writerows(report)
        print(f"\n📄 Report saved: {csv_path}")

def batch_validate(batch_dir: Path, corpus: Dict[str, Any]):
    """Validate all log files in a directory - simple PASS/FAIL output."""
    
    print(f"\n📂 Batch validation: {batch_dir}")
    
    # Find all JSON files
    json_files = list(batch_dir.rglob("*.json"))
    json_gz_files = list(batch_dir.rglob("*.json.gz"))
    all_files = json_files + json_gz_files
    
    if not all_files:
        print("❌ No log files found in directory")
        return
    
    print(f"📊 Found {len(all_files)} files to validate\n")
    
    # Track results
    results = []
    pass_count = 0
    fail_count = 0
    
    for filepath in sorted(all_files):
        events = load_json_file(filepath)
        
        if not events:
            print(f"❌ FAIL - {filepath.name} (no events)")
            fail_count += 1
            results.append({'file': filepath.name, 'status': 'FAIL', 'reason': 'No events'})
            continue
        
        # Validate all events in file
        file_status = 'PASS'
        fail_reasons = []
        
        for event in events:
            if not isinstance(event, dict):
                continue
            
            status, issues = validate_event(event, corpus)
            
            if status == 'FAIL':
                file_status = 'FAIL'
                # Collect unique failure reasons
                for issue in issues:
                    if issue.startswith('❌'):
                        fail_reasons.append(issue.split(':')[0].replace('❌', '').strip())
        
        # Output result
        if file_status == 'PASS':
            print(f"✅ PASS - {filepath.name}")
            pass_count += 1
            results.append({'file': filepath.name, 'status': 'PASS', 'reason': ''})
        else:
            reason = ', '.join(set(fail_reasons))
            print(f"❌ FAIL - {filepath.name}")
            fail_count += 1
            results.append({'file': filepath.name, 'status': 'FAIL', 'reason': reason})
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 BATCH SUMMARY: {pass_count} PASS, {fail_count} FAIL (total: {len(all_files)})")
    print(f"{'='*60}")
    
    if fail_count > 0:
        print(f"\n⚠️  Failed files (validate individually for details):")
        for result in results:
            if result['status'] == 'FAIL':
                print(f"   • {result['file']}")
    else:
        print(f"\n✅ All files passed validation")
    
    # Save batch report
    import csv
    csv_path = Path('batch_validation_report.csv')
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['file', 'status', 'reason'])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n📄 Batch report saved: {csv_path}")

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage:")
        print(f"  BUILD:    {sys.argv[0]} --build /path/to/real/logs/")
        print(f"  APPEND:   {sys.argv[0]} --append /path/to/more/logs/")
        print(f"  VALIDATE: {sys.argv[0]} test.json [--csv]")
        print(f"  BATCH:    {sys.argv[0]} --batch /path/to/test/logs/")
        sys.exit(1)
    
    # Build mode
    if sys.argv[1] == '--build':
        if len(sys.argv) < 3:
            print("❌ Error: --build requires directory path")
            print(f"Usage: {sys.argv[0]} --build /path/to/real/logs/")
            sys.exit(1)
        
        logs_dir = Path(sys.argv[2])
        if not logs_dir.exists() or not logs_dir.is_dir():
            print(f"❌ Error: Directory not found: {logs_dir}")
            sys.exit(1)
        
        corpus = build_corpus(logs_dir)
        save_corpus(corpus)
        sys.exit(0)
    
    # Append mode
    if sys.argv[1] == '--append':
        if len(sys.argv) < 3:
            print("❌ Error: --append requires directory path")
            print(f"Usage: {sys.argv[0]} --append /path/to/more/logs/")
            sys.exit(1)
        
        logs_dir = Path(sys.argv[2])
        if not logs_dir.exists() or not logs_dir.is_dir():
            print(f"❌ Error: Directory not found: {logs_dir}")
            sys.exit(1)
        
        # Load existing corpus
        existing_corpus = load_corpus()
        
        # Append new logs
        corpus = build_corpus(logs_dir, existing_corpus)
        save_corpus(corpus)
        sys.exit(0)
    
    # Batch mode
    if sys.argv[1] == '--batch':
        if len(sys.argv) < 3:
            print("❌ Error: --batch requires directory path")
            print(f"Usage: {sys.argv[0]} --batch /path/to/test/logs/")
            sys.exit(1)
        
        batch_dir = Path(sys.argv[2])
        if not batch_dir.exists() or not batch_dir.is_dir():
            print(f"❌ Error: Directory not found: {batch_dir}")
            sys.exit(1)
        
        corpus = load_corpus()
        batch_validate(batch_dir, corpus)
        sys.exit(0)
    
    # Validate mode
    test_file = Path(sys.argv[1])
    csv_output = '--csv' in sys.argv
    
    if not test_file.exists():
        print(f"❌ Error: File not found: {test_file}")
        sys.exit(1)
    
    corpus = load_corpus()
    validate_file(test_file, corpus, csv_output)

if __name__ == '__main__':
    main()
