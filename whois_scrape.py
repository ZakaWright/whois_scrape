import argparse
from apis import shodan
from apis import whois
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
parser.add_argument('-i', '--ip', help='IP address to lookup')
args = parser.parse_args()

if args.domain is not None:
    # resolve domain
    try:
        command = f'nslookup {args.domain}'
        resolved = subprocess.check_output(command, shell=True, text=True)
    except:
        exit('Error resolving the IP address')

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
        exit('Failed to resolve IP addresses')

    # for testing purposes, only select the first IP address. This is to limit API calls
    # Future implementations of this program need to handle lists of IP addresses... TODO
    args.ip = ips[0]

    # get domain registration information
    try:
        whois.whois_query(args.domain)
    except:
        exit('Error reaching whois information')
