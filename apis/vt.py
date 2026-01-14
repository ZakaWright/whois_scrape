import requests
import os
from dotenv import load_dotenv

def apiKey():
    load_dotenv()
    return os.getenv('VT_API')

def domain_lookup(domain):

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'

    headers = {
        'accept': 'application/json',
        'x-apikey': apiKey()
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return 'Error'
    except:
        return 'Error'


def ip_lookup(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'

    headers = {
        'accept': 'application/json',
        'x-apikey': apiKey()
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return 'Error'
    except:
        return 'Error'
