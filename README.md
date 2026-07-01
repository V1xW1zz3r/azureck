# azureck: Azure Service Tag & IP Range Checker

A Go CLI tool to check if an IP address, domain, or target list belongs to Microsoft Azure Service Tags, CIDR ranges, and geographic regions. 

Easily perform Azure IP lookups, reverse DNS scans, and bulk threat hunting queries to verify if incoming or outgoing traffic originates from legitimate Microsoft Azure infrastructure (such as Azure Blob Storage, Azure Front Door, or App Services, etc).

---

## Features

* **Flexible Target Scanning**: Handles a single IP, a domain/URL (with auto-DNS resolution), or a flat file containing a list of targets (could be IPs and domains mixed).
* **Hybrid Data Loading**:
  * **Offline/Scraper Mode (Default)**: Automatically scrapes Microsoft's weekly updated Service Tag catalog, downloading and caching it locally to run with zero credentials.
  * **Azure API Mode**: Integrates with the official Azure Resource Manager (ARM) SDK using `DefaultAzureCredential` to query real-time SDN metadata from private or sovereign clouds (US Gov, China).

---

## Installation

### Direct Go Installation
```bash
go install github.com/V1xW1zz3r/azureck@latest
```

### Manual Compilation
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
If you want the region lists (**usgov** and **china**) I made a table for it. This be found in my notes [here](https://vix-w1zzer.gitbook.io/vixwizzer/notes/cloud/azure/tool-azureck#authenticated-through-azure-api)

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

---

## Acknowledgments
This project was inspired by [cloudipchecker](https://github.com/deanobalino/cloudipchecker). Because the original tool is currently unmaintained and legacy Azure SDK dependencies have changed, `azureck` was written from the ground up as a modern, high-performance alternative using the current Azure SDK for Go.

### Need more feature? Not satisfied?
You are highly encouraged to suggest features, report bugs, or open a pull request/issue thingie.. idk
