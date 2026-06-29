# Azure Service Tag & IP Range Checker

A simple CLI tool written in Go to map out IP addresses, domain names, or bulk target lists to official Azure Service Tags, system services, and geographic regions. 

This tool serves threat hunting, security operations (SecOps), and firewall audits by identifying whether incoming or outgoing traffic belongs to legitimate Microsoft Azure infrastructure.

---

## Features

* **Flexible Target Scanning**: Handles a single IP, a domain/URL (with auto-DNS resolution), or a flat file containing a list of targets (could be IPs and domains mixed).
* **Hybrid Data Loading**:
  * **Offline/Scraper Mode (Default)**: Automatically scrapes Microsoft's weekly updated Service Tag catalog, downloading and caching it locally to run with zero credentials.
  * **Azure API Mode**: Integrates with the official Azure Resource Manager (ARM) SDK using `DefaultAzureCredential` to query real-time SDN metadata from private or sovereign clouds (US Gov, China).

---

## Installation

### Method 1: Direct Go Installation
```bash
go install github.com/V1xW1zz3r/azureck@latest
```

### Method 2: Manual Compilation
```bash
git clone https://github.com/V1xW1zz3r/azureck.git
cd azureck
go build -o azureck main.go
```

---

## Usage
```text
Usage:
  azureck [flags]

Flags:
  -d    Target input: single IP, single domain/URL, or path to a file containing targets (default: "")
  -f    Path to a local ServiceTags_Public.json file (skips scraping/API lookup) (default: "")
  -s    Azure Subscription ID (Auth mode) (default: "")
  -l    Azure region to query (With auth only) (default: "eastus")
  -t    Timeout duration for network and DNS operations (default: 30s)
  -h    Display help options
```

---

## Examples

### 1. Basic IP Lookup
```bash
azureck -d 20.60.120.10
```

### 2. Domain Lookup
```bash
azureck -d portal.azure.com
```

### 3. Bulk Scan from File
```bash
azureck -d list.txt
```

### 4. Authenticated Azure API Mode
Requires the Azure CLI to be authenticated first. Use `-l` if your subscription restricts control-plane queries to specific regions or if you are scanning within a sovereign/private cloud (e.g., Azure Gov):
```bash
az login

# Standard query
azureck -s "<your_subID>" -d 150.171.84.20

# Sovereign cloud or region restricted policy query
azureck -s "<your_subID>" -l "usgovvirginia" -d 150.171.84.20
```

### 5. Local JSON File Scan
Directly scan against a pre-downloaded offline `ServiceTags_Public.json` file:
```bash
azureck -f ServiceTags_Public_20260622.json -d 20.60.120.10
```