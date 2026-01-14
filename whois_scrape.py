import argparse
from apis import shodan
from apis import whois
from apis import vt
import subprocess
import sys


# helper functions
def exit(reason):
    print(f'{reason}\nExiting...')
    sys.exit()
# Argparse setup
parser = argparse.ArgumentParser(
    prog='Whois_Scraper',
    description='Basic tool to collect information on a domain',
)

#parser.add_argument('domain', help='Domain to lookup')
parser.add_argument('-d', '--domain', help='Domain to lookup')
parser.add_argument('-i', '--ip', help='IP address to lookup. Multiple IPs must be comma separated X.X.X.X,Y.Y.Y.Y')
args = parser.parse_args()

# dictionary to hold data as it's processed
'''
SCHEMA
domain/ip: {
    type: [ip | domain],
    ip: [], # array of IP addresses if domain
    whois: {},
    shodan: {},
    virusTotal: {}
}
'''
indicators = {}

# split IPs if there are multiple
# TODO implement IP validation
if args.ip is not None:
    ips = args.ip.split(',')

    for ip in ips:
        # ensure there are no duplicates
        if ip not in indicators:
            indicators[ip] = {'type': 'ip'}

if args.domain is not None:
    domains = args.domain.split(',')
    for domain in domains:
        indicators[domain] = {'type': 'domain'}
        # resolve domain
        try:
            command = f'nslookup {domain}'
            resolved = subprocess.check_output(command, shell=True, text=True)

            resolved = resolved.split('\n')
            ips = []
            # flag to identify when answers have started to ignore the DNS server address
            answers = False
            for r in resolved:
                if "answer" in r:
                    answers = True
                if answers and r.startswith("Address"):
                    ips.append(r.split(' ')[-1])

            if len(ips) == 0:
                print(f'Failed to resolve IP address for {domain}')
                indicators[domain]['ip'] = "Error"
            else:
                # for testing purposes, only select the first IP address.
                # This is to limit the number of API calls
                indicators[domain]['ip'] = [ips[0]]

        except:
            print(f'Error resolving the IP address for {domain}')
            indicators[domain]['ip'] = "Error"

        # get domain registration information
        try:
            registration = whois.domain_query(domain)
            indicators[domain]['whois'] = registration
        except:
            print(f'Error reaching whois information for {domain}')
            
# IP information
for i in indicators:
    if indicators[i]['type'] == 'ip':
        indicators[i]['whois'] = whois.ip_query(i)
        indicators[i]['shodan'] = shodan.lookup(i)
        indicators[i]['virusTotal'] = vt.ip_lookup(i)
    elif indicators[i]['type'] == 'domain':
        indicators[i]['shodan'] = {}
        for ip in indicators[i]['ip']:
            indicators[i]['shodan'][ip] = shodan.lookup(ip)
        indicators[i]['virusTotal'] = vt.domain_lookup(i)

# Output
for i in indicators:
    type = indicators[i]['type']
    print(f'{i} ({type})')
    if type == 'domain':
        print('\t-------------------------------------------')
        print('\tDNS Resolution')
        print('\t-------------------------------------------')
        print(f'\tIP Addresses: {indicators[i]["ip"]}\n')
        print('\t-------------------------------------------')
        print('\tWhois Information')
        print('\t-------------------------------------------')
        print(f'\tRegistrar: {indicators[i]["whois"]["Registrar"]}')
        print(f'\tUpdated Date: {indicators[i]["whois"]["Updated Date"]}')
        print(f'\tCreation Date: {indicators[i]["whois"]["Creation Date"]}\n')
        print('\t-------------------------------------------')
        print('\tShodan Results')
        print('\t-------------------------------------------')
        for ip in indicators[i]['shodan']:
            print(f'\t{ip}')
            print(f'\t\tOpen Ports: {indicators[i]["shodan"][ip]["ports"]}')
            print(f'\t\tTags: {indicators[i]["shodan"][ip]["tags"]}')
    elif type == 'ip':
        print('\t-------------------------------------------')
        print('\tWhois Information')
        print('\t-------------------------------------------')
        # try statement to handle different fields in whois records
        try:
            print(f'\tNetwork: {indicators[i]["whois"]["CIDR"]}')
        except:
            print(f'\tNetwork: {indicators[i]["whois"]["inetnum"]}')
        try:
            print(f'\tOrganization: {indicators[i]["whois"]["Organization"]}\n')
        except:
            print(f'\tOrganization: {indicators[i]["whois"]["organisation"]}\n')
        print('\t-------------------------------------------')
        print('\tShodan Results')
        print('\t-------------------------------------------')
        print(f'\t\tOpen Ports: {indicators[i]["shodan"]["ports"]}')
        print(f'\t\tTags: {indicators[i]["shodan"]["tags"]}')
    print('\t-------------------------------------------')
    print('\tVirus Total')
    print('\t-------------------------------------------')
    vt_results = indicators[i]['virusTotal']['data']['attributes']['last_analysis_stats']
    #print(indicators[i]['virusTotal']['data']['attributes']['last_analysis_stats'])
    for j in vt_results:
        print(f'\t{j}: {vt_results[j]}')

