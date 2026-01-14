import shodan
import os
from dotenv import load_dotenv
import json

def lookup(ips):
    load_dotenv()
    SHODAN_API = os.getenv('SHODAN_API')
    api = shodan.Shodan(SHODAN_API)

    results = {}
    
    for ip in ips:
        results[ip] = api.host(ip)


    return results

