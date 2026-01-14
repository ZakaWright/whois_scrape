import shodan
import os
from dotenv import load_dotenv
import json

def lookup(ip):
    load_dotenv()
    SHODAN_API = os.getenv('SHODAN_API')
    api = shodan.Shodan(SHODAN_API)

    return api.host(ip)

