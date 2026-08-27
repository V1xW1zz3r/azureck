# azureck: Azure Service Tag & IP Range Checker

A Go CLI tool to check if an IP address, domain, or target list belongs to Microsoft Azure Service Tags, CIDR ranges, and geographic regions. 

It will do IP lookups, reverse DNS scans, and bulk enumeration queries to verify if incoming or outgoing traffic originates from legitimate Microsoft Azure infrastructure (such as Azure Blob Storage, Azure Front Door, or App Services, etc).

For more info you can visit my site [HERE](https://vix-w1zzer.gitbook.io/vixwizzer/notes/cloud/azure/tool-azureck#authenticated-through-azure-api) I talked about available regions and some of my findings on why you'll likely to fail resolve with restricted/private regions.

---

## Features

* **Flexible Scanning**: Handles a single IP, a domain/URL (with auto-DNS resolution), or a flat file with a mix of targets.
* **Multi-Cloud Checks (just added this lol)**: Scans across **Public**, **US Government**, and **China (21Vianet)** ranges so you don't have to guess the cloud partition.
* **Hybrid Data Loading**:
  * **Offline/Scraper Mode (Default)**: Automatically scrapes Microsoft's weekly updated catalogs, downloading and caching them locally (valid for 7 days) to run with zero credentials. (stored in ~/.cache/azureck)
  * **Azure API Mode**: Uses the official Azure Resource Manager (ARM) SDK with `DefaultAzureCredential` to query real-time SDN metadata directly from control-plane controllers.

---

## Installation

### Direct Go Install
```bash
go install github.com/V1xW1zz3r/azureck@latest
```

### Manual Build
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
  -d    Accept inputs: single IP, single domain/URL, or path to a file containing targets (default: "")
  -f    Path to a local ServiceTags.json file (skips scraping/API lookup) (default: "")
  -s    Azure Subscription ID (Auth mode) (default: "")
  -l    Azure region to query (With auth only) (default: "eastus")
  -t    Timeout duration for network and DNS operations (default: 45s)
  -h    Display help options
```

---

## Examples

### 1. Basic IP Lookup
Checks the IP against Public, USGov, and China clouds automatically:
```bash
azureck -d 20.60.120.10
```

### 2. Domain Lookup
Resolves DNS first, then matches the resolved IPs:
```bash
azureck -d portal.azure.com
```

### 3. Bulk Scan from File
Scan a mixed list of IPs and domains from a text file:
```bash
azureck -d list.txt
```

### 4. Authenticated Azure API Mode
Requires the Azure CLI to be authenticated first. Use `-l` if your subscription restricts control-plane queries to specific regions or if you are scanning within a sovereign/private cloud:

```bash
az login

# Standard query
azureck -s "<your_subID>" -d 150.171.84.20

# Sovereign cloud or region-restricted policy query
# This only works if your subID/tenant belongs to that environment
azureck -s "<your_subID>" -l "usgovvirginia" -d 150.171.84.20
```

### 5. Local JSON File Scan
Scan directly against a pre-downloaded offline `ServiceTags.json` file:
```bash
azureck -f ServiceTags_Public_20260622.json -d 20.60.120.10
```

---

## Acknowledgments

This project was inspired by [cloudipchecker](https://github.com/deanobalino/cloudipchecker). Because the original tool is currently unmaintained and legacy Azure SDK dependencies have changed, `azureck` was written from the ground up as a modern, high-performance alternative using the current Azure SDK for Go.

---

### Need more features? Not satisfied?
You are highly encouraged to suggest features, report bugs, or open a pull request/issue thingie... idk
