# Overview
This is a simple script to collect information from multiple sources on a domain or IP address.

# Usage
## Installation
`python3 -m pip install -r requiremnts.txt`

## Flags
Domains and IPs can both be queried with the same command. Specicy a domain with the `-d` or `--domain` flag. Specify an IP address with the `-i` or `--ip` flag.
Multiple IPs and domains can be queried by comma separating the values.

# Example
Running `python3 whois_scrape.py -i 8.8.8.8,1.1.1.1 -d google.com,amazon.com` will have the following output:
```
8.8.8.8 (ip)
	-------------------------------------------
	Whois Information
	-------------------------------------------
	Network: 8.8.8.0/24
	Organization: Google LLC (GOGL)

	-------------------------------------------
	Shodan Results
	-------------------------------------------
		Open Ports: [443, 53]
		Tags: []
	-------------------------------------------
	Virus Total
	-------------------------------------------
	malicious: 0
	suspicious: 0
	undetected: 30
	harmless: 63
	timeout: 0
1.1.1.1 (ip)
	-------------------------------------------
	Whois Information
	-------------------------------------------
	Network: 1.1.1.0 - 1.1.1.255
	Organization: ORG-ARAD1-AP

	-------------------------------------------
	Shodan Results
	-------------------------------------------
		Open Ports: [161, 2082, 2083, 2052, 2053, 2086, 2087, 2095, 80, 8880, 8080, 53, 8443, 443, 2096]
		Tags: []
	-------------------------------------------
	Virus Total
	-------------------------------------------
	malicious: 0
	suspicious: 0
	undetected: 29
	harmless: 64
	timeout: 0
google.com (domain)
	-------------------------------------------
	DNS Resolution
	-------------------------------------------
	IP Addresses: ['142.250.152.100']

	-------------------------------------------
	Whois Information
	-------------------------------------------
	Registrar: MarkMonitor Inc.
	Updated Date: 2019-09-09T15:39:04Z
	Creation Date: 1997-09-15T04:00:00Z

	-------------------------------------------
	Shodan Results
	-------------------------------------------
	142.250.152.100
		Open Ports: [80, 443]
		Tags: ['self-signed']
	-------------------------------------------
	Virus Total
	-------------------------------------------
	malicious: 1
	suspicious: 0
	undetected: 25
	harmless: 67
	timeout: 0
amazon.com (domain)
	-------------------------------------------
	DNS Resolution
	-------------------------------------------
	IP Addresses: ['98.87.170.71']

	-------------------------------------------
	Whois Information
	-------------------------------------------
	Registrar: MarkMonitor Inc.
	Updated Date: 2025-07-31T17:49:55Z
	Creation Date: 1994-11-01T05:00:00Z

	-------------------------------------------
	Shodan Results
	-------------------------------------------
	98.87.170.71
		Open Ports: [80, 443]
		Tags: ['cloud']
	-------------------------------------------
	Virus Total
	-------------------------------------------
	malicious: 0
	suspicious: 0
	undetected: 26
	harmless: 67
	timeout: 0
```

