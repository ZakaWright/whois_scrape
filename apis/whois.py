import subprocess


def parse_domain(response):
    whois = {}
    response = response.split('\n')

    # flag for when the notice starts
    notice = False

    # TODO add some way to process multiples of fields (eg. Domain Status and Name Server)
    # simplest way will probably be to do a for loop to check if the value exists in the dict and convert to a list if not already

    for line in response:
        if '>>>' in line:
            notice = True
            # process last update
            # >>> Last update of whois database: 2026-01-13T04:09:34Z <<<
            split = line.split(':', 1)[1]
            time = split.split('<')[0].strip()
            whois['Last Update'] = time
        if not notice:
            split = line.split(':', 1)
            field = split[0].strip()
            value = split[1].strip()
            whois[field] = value
    return whois

    
def domain_query(domain):
    # should only return one record. The -H flag does not show legal information
    command = f'whois "domain {domain}" -H'
    response = subprocess.check_output(command, shell=True, text=True)
    return parse_domain(response)

def parse_ip(response):
    whois = {}
    response = response.split('\n')

    # whois information for IPs can have different formats. The try statements help to bypass any issues
    # future implemenations can handle different formats
    for line in response:
        if line.startswith("#") or line == '' or line.startswith('%'):
            continue
        try:
            split = line.split(':', 1)
            field = split[0].strip()
            value = split[1].strip()
            whois[field] = value
        except:
            continue
    return whois


def ip_query(ip):
    command = f'whois {ip}'
    response = subprocess.check_output(command, shell=True, text=True)
    return parse_ip(response)
