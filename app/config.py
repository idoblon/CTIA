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
OTX_KEY = os.getenv('OTX_KEY')

# Automation Configuration (Phase 8)
AUTOMATION_ENABLED = os.getenv('AUTOMATION_ENABLED', 'true').lower() == 'true'
ENRICHMENT_BATCH_SIZE = int(os.getenv('ENRICHMENT_BATCH_SIZE', '50'))
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', '75'))

# Email Alert Configuration (Optional)
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
ALERT_EMAIL_FROM = os.getenv('ALERT_EMAIL_FROM')
ALERT_EMAIL_TO = os.getenv('ALERT_EMAIL_TO')