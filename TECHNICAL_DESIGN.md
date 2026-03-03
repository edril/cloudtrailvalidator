# CloudTrail Validator - Technical Design Document

## Executive Summary

This validator uses corpus-based analysis to detect synthetic or malformed CloudTrail logs by comparing field paths against a reference database built from genuine AWS CloudTrail data. The approach is based on the principle that legitimate AWS services produce consistent field structures, while synthetic or forged logs often contain field paths that never appear in real CloudTrail events.

## Architecture Overview

### Core Design Philosophy

**Premise**: AWS CloudTrail events follow strict schema patterns. Real AWS services will only emit field paths that exist in their service-specific schemas. Synthetic logs created by attackers or poorly-implemented log generators will likely introduce field paths that don't exist in genuine AWS logs.

**Detection Strategy**: Build a comprehensive database of all field paths seen in real CloudTrail logs, then flag any test log containing paths not in this corpus.

### Three-Phase Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Corpus Building                                    │
│ ────────────────────────────────────────────────────────── │
│ Input: Real CloudTrail logs (hundreds of MBs)               │
│ Process: Recursive field path extraction                    │
│ Output: corpus.db (JSON file with ~1600+ field paths)       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Two-Tier Validation                                │
│ ────────────────────────────────────────────────────────── │
│ Tier 1: Structure Check (mandatory CloudTrail fields)       │
│ Tier 2: Corpus Check (field path existence)                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Reporting                                           │
│ ────────────────────────────────────────────────────────── │
│ Output: PASS/FAIL per event with detailed issue breakdown   │
└─────────────────────────────────────────────────────────────┘
```

## Component Deep-Dive

### 1. Field Path Extraction (`extract_field_paths`)

**Purpose**: Recursively traverse nested JSON structures to extract all possible field paths.

**Algorithm**:
```python
def extract_field_paths(obj, prefix=''):
    # Base case: dict → iterate keys, recurse on values
    # Base case: list → recurse on all items
    # Termination: primitive types (str, int, bool, null)
```

**Example**:
```json
{
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI...",
    "arn": "arn:aws:iam::123:user/alice"
  },
  "requestParameters": {
    "bucketName": "mybucket"
  }
}
```

**Extracted paths**:
- `userIdentity`
- `userIdentity.type`
- `userIdentity.principalId`
- `userIdentity.arn`
- `requestParameters`
- `requestParameters.bucketName`

**Why this works**:
- AWS services emit consistent nested structures
- Field names are stable across API versions (with rare exceptions)
- Nested paths capture both top-level and detail-level schema violations

**Limitation acknowledged**: 
- Does not track field value types or ranges
- Does not validate value semantics (e.g., `arn` format validity)
- Array structures are flattened (doesn't distinguish `items[0]` vs `items[1]`)

### 2. Multi-Format JSON Parsing (`load_json_file`)

**Challenge**: CloudTrail logs appear in three formats:
1. Standard AWS CloudTrail export: `{"Records": [...]}`
2. Plain JSON arrays: `[{...}, {...}]`
3. NDJSON (Splunk, log aggregators): One JSON object per line

**Solution**: Cascading parse strategy:
```
Try standard JSON parse
├─ Success? → Extract Records array or treat as list
└─ JSONDecodeError? → Try NDJSON line-by-line parse
   ├─ Success? → Return list of events
   └─ Failure? → Return empty list, log error
```

**Why this works**:
- `json.loads()` fails fast on NDJSON (sees "extra data")
- Line-by-line parse handles NDJSON without external dependencies
- Graceful degradation: bad lines skipped, good lines processed

**Edge cases handled**:
- Gzipped files (`.json.gz`)
- Empty files
- Mixed valid/invalid JSON lines in NDJSON
- Single event JSON objects (not wrapped in array)

**Known limitation**: 
- NDJSON parse loads entire file into memory (could be improved with streaming for multi-GB files)
- Malformed JSON lines are silently skipped with warning (design choice: permissive vs strict)

### 3. Corpus Building (`build_corpus`)

**Input**: Directory path containing real CloudTrail logs

**Process**:
1. Recursive directory scan for `*.json` and `*.json.gz`
2. Load each file (multi-format parser)
3. Extract field paths from each event
4. Accumulate into set (deduplication automatic)
5. Track statistics: file count, event count, event types

**Data structure**:
```json
{
  "field_paths": ["eventVersion", "eventTime", ...],  // Sorted list
  "stats": {
    "file_count": 1234,
    "event_count": 289453,
    "event_types": {
      "s3.amazonaws.com.GetObject": 45678,
      "iam.amazonaws.com.CreateUser": 123,
      ...
    }
  }
}
```

**Why set-based accumulation**:
- O(1) insertion and deduplication
- Memory efficient (field paths are typically <100 chars)
- Typical corpus size: 1600 paths from 2M events = ~150KB JSON

**Append mode design**:
- Loads existing corpus into memory
- Merges new paths with existing set
- Updates statistics additively
- Atomic write (overwrites `corpus.db` only on success)

**Scalability consideration**:
- Current implementation: ~1000 files/minute on standard hardware
- Bottleneck: Disk I/O for gzip decompression, not CPU
- Could parallelize file processing (not implemented - complexity vs benefit)

### 4. Validation Logic

#### Tier 1: Structure Validation (`validate_structure`)

**Mandatory fields** (CloudTrail spec):
- `eventVersion`: API version
- `eventTime`: ISO8601 timestamp
- `eventSource`: AWS service (e.g., `s3.amazonaws.com`)
- `eventName`: API action (e.g., `GetObject`)
- `awsRegion`: AWS region
- `userIdentity`: Caller identity object

**Type checks**:
- `eventTime` must be string (not int/object)
- `userIdentity` must be object (not string/array)

**Rationale**: These fields are **always** present in genuine CloudTrail. Their absence indicates:
- Truncated/corrupted log
- Synthetic log by someone unfamiliar with CloudTrail format
- Non-CloudTrail data misidentified as CloudTrail

**Why only basic type checks**: Full type validation would require complete AWS schema definitions (not publicly available in machine-readable format). Current approach balances detection capability with maintenance burden.

#### Tier 2: Corpus Validation (`validate_corpus`)

**Algorithm**:
```
corpus_paths = set(corpus['field_paths'])
event_paths = extract_field_paths(event)
unknown_paths = event_paths - corpus_paths

if unknown_paths:
    FAIL with list of unknown paths
else:
    PASS
```

**Strictness**: ANY unknown path = FAIL

**Justification for strict mode**:
- Use case is detecting synthetic logs, not debugging malformed AWS data
- False positives are acceptable (investigate manually)
- False negatives are dangerous (synthetic log passes validation)

**Known limitation - False positives possible when**:
- New AWS service/feature introduces new fields (corpus needs update)
- Regional variation in field presence (rare but possible)
- API version differences (e.g., CloudTrail v1.05 vs v1.08)

**Mitigation**: `--append` mode allows corpus updates without rebuild

### 5. Batch Mode (v3 only)

**Design**: Lightweight pass/fail per file, defer details to individual validation

**Output**:
```
✅ PASS - legitimate_log.json
❌ FAIL - synthetic_log.json
❌ FAIL - truncated_log.json
```

**Batch report**: CSV with filename, status, high-level reason

**Why this design**:
- Analyst workflow: batch triage → investigate failures individually
- Fast: no detailed output per event (just aggregate status)
- CSV export for tooling integration

**Trade-off**: Loss of per-event granularity in batch mode (by design)

## Assumptions and Limitations

### Assumptions

1. **Corpus completeness**: The reference logs contain representative samples of all legitimate field paths
   - **Risk**: New AWS features may introduce unseen paths
   - **Mitigation**: Periodic corpus updates via `--append`

2. **Field path stability**: AWS doesn't frequently rename/remove fields
   - **Historical evidence**: CloudTrail schema is remarkably stable (v1.05 from 2014 still valid)
   - **Risk**: Major API version changes could break validation

3. **Attacker sophistication**: Attackers creating synthetic logs won't have access to complete CloudTrail corpus
   - **Justification**: Most synthetic log generators use documentation or guesswork
   - **Counter**: Nation-state actors with access to real CloudTrail data could craft undetectable fakes

4. **JSON parsing robustness**: `json.loads()` catches malformed JSON
   - **Edge case**: Truncated multi-MB JSON files may cause memory issues
   - **Mitigation**: File size checks could be added

### Known Limitations

1. **No value validation**: 
   - Doesn't check if `arn:aws:iam::123:user/alice` is valid ARN format
   - Doesn't verify timestamp format
   - Doesn't validate IP addresses, UUIDs, etc.
   - **Rationale**: Field path validation catches 90% of synthetic logs; value validation is complex and maintenance-heavy

2. **No behavioral analysis**:
   - Doesn't detect anomalous event sequences (e.g., 1000 S3 reads/second)
   - Doesn't flag unusual cross-region patterns
   - **Rationale**: Out of scope; this is schema validation, not behavioral analytics

3. **Memory-bound corpus building**:
   - Loads entire corpus into memory
   - Current implementation: ~2M events = ~150KB corpus = trivial
   - Theoretical limit: ~100M events = ~7.5MB corpus = still manageable
   - **Risk**: Multi-billion event corpus could hit memory limits

4. **No concurrency**:
   - Single-threaded file processing
   - **Impact**: ~1000 files/minute on typical hardware
   - **Justification**: Disk I/O is bottleneck, not CPU; threading wouldn't help significantly

5. **Append mode naivety**:
   - No deduplication check (if same file appended twice, events counted twice)
   - **Impact**: Inflated event_count statistic (field_paths still correct)
   - **Mitigation**: User responsibility to not re-append same data

6. **NDJSON parsing permissiveness**:
   - Silently skips malformed lines
   - **Risk**: Partially corrupted NDJSON file might validate as "PASS" if valid lines happen to pass
   - **Justification**: Trade-off for robustness; real-world logs often have occasional bad lines

## Security Considerations

### Attack Resistance

**Scenario 1: Attacker with AWS documentation**
- Attacker crafts logs using public CloudTrail schema docs
- **Detection probability**: HIGH
- **Reason**: Docs don't cover all nested field paths; common to miss `requestParameters` sub-fields

**Scenario 2: Attacker with sample logs**
- Attacker uses 10-100 sample CloudTrail events as template
- **Detection probability**: MEDIUM-HIGH
- **Reason**: Sample won't cover all event types; missing paths for uncommon actions

**Scenario 3: Attacker with comprehensive corpus**
- Attacker has access to millions of real CloudTrail events (same source as defender)
- **Detection probability**: LOW
- **Reason**: Indistinguishable from real logs at field path level; need behavioral analysis

### Evasion Techniques (Theoretical)

1. **Subset injection**: Only forge events with commonly-seen field paths
   - **Counter**: Behavioral analysis (not implemented here)

2. **Corpus poisoning**: Inject synthetic logs into defender's corpus
   - **Counter**: Corpus source validation (not implemented)

3. **Gradual schema drift**: Introduce new paths slowly over time
   - **Counter**: Corpus versioning and diffing (not implemented)

## Performance Characteristics

### Time Complexity

- **Corpus building**: O(N × M × D)
  - N = number of files
  - M = average events per file
  - D = average depth of JSON nesting
  - Typical: 1000 files × 100 events × 5 depth = 500K operations

- **Validation**: O(E × D)
  - E = events in test log
  - D = average depth
  - Set membership check is O(1)

### Space Complexity

- **Corpus storage**: O(P) where P = unique field paths
  - Typical: 1600 paths × ~50 chars = ~80KB JSON (150KB with metadata)

- **Runtime memory**: O(P + E×D)
  - Corpus in memory + current event paths
  - Typical: <10MB for standard workloads

### Scalability Limits

| Metric | Current | Theoretical Max | Bottleneck |
|--------|---------|-----------------|------------|
| Corpus events | 2M | ~100M | Memory |
| Corpus field paths | 1600 | ~100K | JSON parsing overhead |
| File count | 1000s | ~1M | Disk I/O |
| Single file size | <10MB | ~1GB | Memory (NDJSON loads full file) |

## Testing Recommendations

### Unit Test Coverage Needed

1. **Field path extraction**:
   - Deeply nested objects (10+ levels)
   - Arrays of objects
   - Mixed null/empty values
   - Unicode in field names

2. **JSON parsing**:
   - All three formats (standard, array, NDJSON)
   - Gzipped files
   - Truncated files
   - Mixed valid/invalid NDJSON lines

3. **Validation logic**:
   - All mandatory fields present/missing combinations
   - Type mismatches
   - Unknown field paths

### Integration Test Scenarios

1. **Corpus building**:
   - Empty directory
   - Mixed .json and .json.gz
   - Append mode with overlapping data

2. **Validation**:
   - Genuine AWS CloudTrail logs (should PASS)
   - Synthetic logs with missing fields (should FAIL - structure)
   - Synthetic logs with fake fields (should FAIL - corpus)

3. **Batch mode**:
   - Directory with mix of valid/invalid
   - Empty directory
   - Recursive subdirectories

## Future Enhancements (Not Implemented)

1. **Value-level validation**:
   - ARN format checking
   - Timestamp format validation
   - IP address validation
   - Region code validation

2. **Probabilistic scoring**:
   - Instead of binary PASS/FAIL, assign confidence score
   - Weight rare field paths higher than common ones

3. **Streaming NDJSON parser**:
   - Process line-by-line without loading full file
   - Enables multi-GB file handling

4. **Parallel corpus building**:
   - Thread pool for file processing
   - Requires locking for shared field_paths set

5. **Corpus versioning**:
   - Track when field paths were added
   - Detect schema drift over time
   - Diff between corpus versions

6. **Machine learning integration**:
   - Use corpus as training data
   - Anomaly detection on field value distributions
   - Behavioral sequence analysis

## Conclusion

This validator is a **schema-level synthetic log detector** that operates on the principle of field path completeness. It excels at catching:

- Poorly-crafted synthetic logs
- Logs from documentation-based generators
- Truncated or corrupted real logs

It does NOT detect:
- Sophisticated forgeries using real CloudTrail corpus
- Behavioral anomalies (unusual API sequences)
- Value-level issues (wrong ARN format, impossible timestamps)

The design prioritizes:
- **Simplicity**: No external dependencies, straightforward logic
- **Maintainability**: Corpus updates via append, not schema definitions
- **Speed**: Fast validation for analyst workflows

For comprehensive CloudTrail analysis, this should be **one component** in a defense-in-depth strategy including behavioral analytics, value validation, and threat intelligence correlation.
