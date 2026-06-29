package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

type ServiceTag struct {
	Name          string   `json:"name"`
	ID            string   `json:"id"`
	Region        string   `json:"region"`
	SystemService string   `json:"systemService"`
	IPPrefixes    []string `json:"addressPrefixes"`
}

type PublicJSONTags struct {
	Values []struct {
		Name       string `json:"name"`
		ID         string `json:"id"`
		Properties struct {
			Region          string   `json:"region"`
			SystemService   string   `json:"systemService"`
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	} `json:"values"`
}

type MatchedTag struct {
	Name          string
	Region        string
	MatchedRange  string
	SystemService string
}

type ResolvedTarget struct {
	IP      string
	Sources []string // track domains/files that led to the IP
}

type ScanResult struct {
	IP      string
	Sources []string
	Matched bool
	Tags    []MatchedTag
}

func main() {
	// define some flags
	dataFlag := flag.String("d", "", "Target input: single IP, single domain/URL, or path to a file containing targets")
	localFile := flag.String("f", "", "Path to a local ServiceTags_Public.json file (skips scraping/API lookup)")
	subID := flag.String("s", os.Getenv("AZURE_SUBSCRIPTION_ID"), "Azure Subscription ID (Auth mode)")
	location := flag.String("l", "eastus", "Azure region to query (With auth only)")
	timeout := flag.Duration("t", 30*time.Second, "Timeout duration for network and DNS operations")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Azure Service Tag & IP Range Checker\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  azureck [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "  -%s\t%s (default: %q)\n", f.Name, f.Usage, f.DefValue)
		})
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  - Scan a single IP address:\n")
		fmt.Fprintf(os.Stderr, "    ./azureck -d 20.60.120.10\n\n")
		fmt.Fprintf(os.Stderr, "  - Scan a domain name (automatic resolution):\n")
		fmt.Fprintf(os.Stderr, "    ./azureck -d portal.azure.com\n\n")
		fmt.Fprintf(os.Stderr, "  - Bulk scan using a target file list:\n")
		fmt.Fprintf(os.Stderr, "    ./azureck -d ips_and_domains.txt\n\n")
		fmt.Fprintf(os.Stderr, "  - Execute in offline mode with a downloaded JSON:\n")
		fmt.Fprintf(os.Stderr, "    ./azureck -f ServiceTags_Public_20260622.json -d 20.60.120.10\n")
	}

	flag.Parse()

	if *dataFlag == "" {
		fmt.Fprintln(os.Stderr, "[!] Error: You must provide a target via the -d flag.")
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// get targets (Files, IPs, and Domains)
	targets, err := gatherTargets(ctx, *dataFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error parsing targets: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] Error: No valid targets found to scan.")
		os.Exit(1)
	}

	// load service tag database
	tags, err := loadServiceTags(ctx, *localFile, *subID, *location)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error loading service tags: %v\n", err)
		if *subID != "" && strings.Contains(err.Error(), "failed to acquire a token") {
			fmt.Println("\nTo use API mode (-s), you must be authenticated. Please run 'az login' locally or pass a local file with '-f' to run offline.")
		}
		os.Exit(1)
	}

	fmt.Println("[*] Matching targets against Azure Service Tags...")
	var results []ScanResult
	for _, target := range targets {
		res, err := scanIP(target.IP, tags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error scanning IP %s: %v\n", target.IP, err)
			continue
		}
		res.Sources = target.Sources
		results = append(results, res)
	}

	printResultsTable(results)
}

func gatherTargets(ctx context.Context, input string) ([]ResolvedTarget, error) {
	var rawInputs []string

	// check if the input points to a valid file on disk
	info, err := os.Stat(input)
	if err == nil && !info.IsDir() {
		file, err := os.Open(input)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", input, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rawInputs = append(rawInputs, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading target file: %w", err)
		}
		fmt.Printf("[*] Loaded %d targets from file: %s\n", len(rawInputs), input)
	} else {
		rawInputs = []string{input}
	}

	ipMap := make(map[string][]string)

	for _, raw := range rawInputs {
		if ip := net.ParseIP(raw); ip != nil {
			ipStr := ip.String()
			ipMap[ipStr] = append(ipMap[ipStr], raw)
			continue
		}

		host, resolvedIPs, err := resolveDomain(ctx, raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to resolve '%s': %v\n", raw, err)
			continue
		}

		for _, rip := range resolvedIPs {
			ipMap[rip] = append(ipMap[rip], host)
		}
	}

	var targets []ResolvedTarget
	for ip, sources := range ipMap {
		srcSet := make(map[string]bool)
		var uniqueSrcs []string
		for _, s := range sources {
			if !srcSet[s] {
				srcSet[s] = true
				uniqueSrcs = append(uniqueSrcs, s)
			}
		}

		targets = append(targets, ResolvedTarget{
			IP:      ip,
			Sources: uniqueSrcs,
		})
	}

	return targets, nil
}

func resolveDomain(ctx context.Context, rawURL string) (string, []string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", nil, fmt.Errorf("invalid structure: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		host = u.Path
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return host, nil, err
	}

	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	return host, ipStrs, nil
}

func loadServiceTags(ctx context.Context, localFile, subscriptionID, location string) ([]ServiceTag, error) {
	if localFile != "" {
		fmt.Printf("[*] Mode: Offline (Using file: %s)\n", localFile)
		return loadFromJSONFile(localFile)
	}

	if subscriptionID != "" {
		fmt.Printf("[*] Mode: Azure API (Subscription: %s)\n", subscriptionID)
		return fetchTagsFromARM(ctx, subscriptionID, location)
	}

	cachePath, err := getCacheFilePath()
	if err != nil {
		return nil, err
	}

	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < 7*24*time.Hour {
			fmt.Printf("[*] Mode: Cache (Using local cache: %s)\n", cachePath)
			return loadFromJSONFile(cachePath)
		}
	}

	fmt.Println("[*] Cache is empty/stale. Scraping Microsoft Download Center...")
	downloadURL, err := scrapeDownloadURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("scraping failed: %w", err)
	}

	fmt.Printf("[*] Downloading service tags from: %s\n", downloadURL)
	return downloadAndCacheTags(ctx, downloadURL, cachePath)
}

func loadFromJSONFile(path string) ([]ServiceTag, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var raw PublicJSONTags
	if err := json.NewDecoder(file).Decode(&raw); err != nil {
		return nil, err
	}

	var tags []ServiceTag
	for _, val := range raw.Values {
		tags = append(tags, ServiceTag{
			Name:          val.Name,
			ID:            val.ID,
			Region:        val.Properties.Region,
			SystemService: val.Properties.SystemService,
			IPPrefixes:    val.Properties.AddressPrefixes,
		})
	}
	return tags, nil
}

func scrapeDownloadURL(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.microsoft.com/en-us/download/details.aspx?id=56519", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("microsoft download page returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`https://download\.microsoft\.com/download/[A-Fa-f0-9/_-]+/ServiceTags_Public_\d{8}\.json`)
	match := re.FindString(string(body))
	if match == "" {
		return "", fmt.Errorf("regex failed to isolate download link")
	}

	return match, nil
}

func downloadAndCacheTags(ctx context.Context, url, cachePath string) ([]ServiceTag, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	tempFile, err := os.CreateTemp("", "azure_tags_*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		return nil, err
	}

	_, err = tempFile.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	var raw PublicJSONTags
	if err := json.NewDecoder(tempFile).Decode(&raw); err != nil {
		return nil, err
	}

	out, err := os.Create(cachePath)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	_, err = tempFile.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(out, tempFile); err != nil {
		return nil, err
	}

	var tags []ServiceTag
	for _, val := range raw.Values {
		tags = append(tags, ServiceTag{
			Name:          val.Name,
			ID:            val.ID,
			Region:        val.Properties.Region,
			SystemService: val.Properties.SystemService,
			IPPrefixes:    val.Properties.AddressPrefixes,
		})
	}
	return tags, nil
}

func fetchTagsFromARM(ctx context.Context, subscriptionID, location string) ([]ServiceTag, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("credential error: %w", err)
	}

	client, err := armnetwork.NewServiceTagsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("client creation failed: %w", err)
	}

	resp, err := client.List(ctx, location, nil)
	if err != nil {
		return nil, fmt.Errorf("control plane query failed: %w", err)
	}

	var tags []ServiceTag
	for _, val := range resp.Values {
		if val == nil || val.Properties == nil {
			continue
		}

		var name, id, region, sysSvc string
		if val.Name != nil {
			name = *val.Name
		}
		if val.ID != nil {
			id = *val.ID
		}
		if val.Properties.Region != nil {
			region = *val.Properties.Region
		}
		if val.Properties.SystemService != nil {
			sysSvc = *val.Properties.SystemService
		}

		var prefixes []string
		for _, prefix := range val.Properties.AddressPrefixes {
			if prefix != nil {
				prefixes = append(prefixes, *prefix)
			}
		}

		tags = append(tags, ServiceTag{
			Name:          name,
			ID:            id,
			Region:        region,
			SystemService: sysSvc,
			IPPrefixes:    prefixes,
		})
	}

	return tags, nil
}

func getCacheFilePath() (string, error) {
	userCache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(userCache, "azure-ip-checker")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "service_tags.json"), nil
}

func scanIP(targetIPStr string, tags []ServiceTag) (ScanResult, error) {
	ip := net.ParseIP(targetIPStr)
	if ip == nil {
		return ScanResult{}, errors.New("invalid format")
	}

	res := ScanResult{
		IP:      targetIPStr,
		Matched: false,
	}

	for _, tag := range tags {
		for _, prefix := range tag.IPPrefixes {
			_, subnet, err := net.ParseCIDR(prefix)
			if err != nil {
				continue
			}

			if subnet.Contains(ip) {
				res.Matched = true
				res.Tags = append(res.Tags, MatchedTag{
					Name:          tag.Name,
					Region:        tag.Region,
					MatchedRange:  prefix,
					SystemService: tag.SystemService,
				})
			}
		}
	}

	return res, nil
}

func printResultsTable(results []ScanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "TARGET IP\tSOURCE(S)\tAZURE?\tSERVICE TAG\tREGION\tSYSTEM SERVICE\tMATCHED CIDR")
	fmt.Fprintln(w, "---------\t---------\t------\t-----------\t------\t--------------\t------------")

	for _, res := range results {
		sourcesStr := strings.Join(res.Sources, ", ")
		if !res.Matched {
			fmt.Fprintf(w, "%s\t%s\tNo\t-\t-\t-\t-\n", res.IP, sourcesStr)
			continue
		}

		for _, tag := range res.Tags {
			region := tag.Region
			if region == "" {
				region = "global"
			}
			svc := tag.SystemService
			if svc == "" {
				svc = "N/A"
			}
			fmt.Fprintf(w, "%s\t%s\tYes\t%s\t%s\t%s\t%s\n", res.IP, sourcesStr, tag.Name, region, svc, tag.MatchedRange)
		}
	}
	w.Flush()
}
