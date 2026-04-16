import os
from dotenv import load_dotenv

# Cargar variables de entorno al iniciar
load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")