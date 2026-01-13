import shodan
import os
from dotenv import load_dotenv

def test():
    load_dotenv()
    SHODAN_API = os.getenv('SHODAN_API')
    print(SHODAN_API)
