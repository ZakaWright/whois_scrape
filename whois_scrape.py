import argparse
from apis import shodan

# Argparse setup
parser = argparse.ArgumentParser(
    prog='Whois_Scraper',
    description='Basic tool to collect information on a domain',
)

#parser.add_argument('domain', help='Domain to lookup')
parser.add_argument('-d', '--domain', help='Domain to lookup')
parser.add_argument('-i', '--ip', help='IP address to lookup')
args = parser.parse_args()

print(args)

shodan.test()
