import os

from dotenv import load_dotenv
from os import getenv
load_dotenv()


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'db', 'cti.db')
LOGO_PATHS = [
'/mnt/data/cti.png',
'/mnt/data/A_logo_for_"Cyber_Threat_Intelligence_Automation"_.png',
'/mnt/data/A_2D_digital_vector_logo_design_represents_Cyber_T.png'
]


VT_API_KEY = os.getenv('VT_API_KEY')
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')