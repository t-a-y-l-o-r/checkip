# checkip ![Main](https://github.com/t-a-y-l-o-r/checkip/workflows/Main/badge.svg) ![Dev](https://github.com/t-a-y-l-o-r/checkip/workflows/Dev/badge.svg)

A CLI tool for IP address threat intelligence. Aggregates data from multiple security APIs in parallel to build a consolidated report on any IPv4 address — including reputation scores, geo-location, associated domains, and passive/active DNS records.

---

## Features

- **Multi-source analysis** — queries VirusTotal, AlienVault OTX, and Robtex concurrently
- **Async pipeline** — all API calls run in parallel via `asyncio` + `aiohttp`
- **Smart deduplication** — tracks previously scanned IPs in a local record to avoid redundant API calls
- **Flexible input** — scan a single IP, resolve a hostname, or batch-scan from a file
- **Structured output** — results are printed to the terminal and saved to `report.json`

---

## Data Sources

| Source | Provides |
|---|---|
| [VirusTotal](https://www.virustotal.com) | Malicious/harmless/suspicious verdict, AS owner, related hostnames |
| [AlienVault OTX](https://otx.alienvault.com) | Threat score, country/city, activity types, reputation, associated URLs |
| [Robtex](https://www.robtex.com) | ASN info, WHOIS, BGP route, passive DNS, active DNS |

---

## Installation

**Requirements:** Python 3.7+

```bash
git clone https://github.com/t-a-y-l-o-r/checkip.git
cd checkip
pip install -r requirements.txt
```

---

## Configuration

VirusTotal and OTX API keys are required. Robtex uses a free public API with no key needed.

Obtain keys from their official sites:
- VirusTotal: [virustotal.com](https://www.virustotal.com) > Profile > API Key
- OTX: [otx.alienvault.com](https://otx.alienvault.com) > Settings > API Key

Keys are resolved in the following priority order:

**1. Environment variables**
```bash
export VIRUS_TOTAL_KEY=your_key_here
export OTX_KEY=your_key_here
```

**2. `~/.checkip/config.ini`** (user-level, recommended)

**3. `./config.ini`** (directory-level)

`config.ini` format:
```ini
[VIRUS_TOTAL]
key=your_key_here

[OTX]
key=your_key_here
```

> Note: Be mindful of each API's rate limits and Terms of Service.

---

## Usage

Run from the `src/` directory:

```bash
cd src/
```

**Scan a single IP**
```bash
python checkip.py -ip 8.8.8.8
```

**Resolve and scan a hostname**
```bash
python checkip.py -u google.com
```

**Batch scan from a file** (newline-delimited IPs)
```bash
python checkip.py -if targets.txt
```

**Force rescan** (ignore previously scanned record)
```bash
python checkip.py -ip 8.8.8.8 -f
```

**Silent mode** (no terminal output, still writes `report.json`)
```bash
python checkip.py -ip 8.8.8.8 -s
```

### All Flags

| Flag | Description |
|---|---|
| `-ip <x.x.x.x>` | Single IPv4 address to scan. Required if `-if` is not set. |
| `-if <file>` | Path to a newline-delimited file of IPs. Required if `-ip` is not set. |
| `-u <url>` | Hostname to resolve to an IP and scan. |
| `-f` / `--force` | Scan all IPs even if a prior record exists. |
| `-s` / `--silent` | Suppress all terminal output. |
| `-v` / `--verbose` | Enable extra output. |
| `-h` / `--help` | Show help message. |

---

## Output

Results are printed per-IP to the terminal and written to `report.json` in the working directory. Previously scanned IPs are tracked in `record.json` — use `-f` to bypass this cache.

Example terminal output structure:
```
    =============================
    [ip]  8.8.8.8  [ip]
    =============================

    ------------------
    Virus Total
    ------------------
[checked] harmless ✅
[owner]   Google LLC
[status]  {'harmless': 87, 'malicious': 0, ...}

    ------------------
    OTX
    ------------------
[asn]           AS15169
[Country]       United States
[City]          ...

    ------------------
    Robtex
    ------------------
[asname]   GOOGLE
[whois]    Google LLC
[country]  US
...
```

---

## Project Structure

```
src/
├── checkip.py              # Entry point and pipeline orchestrator
├── collectors/
│   ├── collectors.py       # Abstract base classes (Collector, Caller, Parser)
│   ├── factory.py          # Collector_Factory — builds collectors from config
│   ├── virus_total.py      # VirusTotal collector
│   ├── otx.py              # AlienVault OTX collector
│   └── robtex.py           # Robtex collector
├── config/                 # Configuration engine (env vars + config.ini)
├── reader/                 # Reads IP input files and the scan record
├── report/                 # Writes report.json and record.json
├── ui/                     # Argument parsing and terminal display
└── tests/                  # Unit tests for all modules
```

Each collector follows the same pattern: a `Caller` makes async HTTP requests, a `Parser` normalizes the response, and both are composed into a `Collector` via the abstract `Collector_Factory`.

---

## Testing

```bash
# Run all tests
./test.sh

# Run with coverage
coverage run -m pytest src/
coverage report
```

---

## Troubleshooting

### macOS
See the [macos issues](https://github.com/t-a-y-l-o-r/checkip/issues?q=label%3Amacos+) for platform-specific help.
