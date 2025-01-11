# PUBLIC_IP OR DOMAIN RELATED SETTINGS
PUBLIC_IP = None

# Construct the full URL for the authentication endpoint
BASE_URL = f"http://{PUBLIC_IP if PUBLIC_IP else 'localhost'}:8000"
AUTH_SERVER_LOGIN_URL = f"{BASE_URL}/fanaAuthenticator/api/token/"
WSL_SERVER_URL = f"http://{PUBLIC_IP if PUBLIC_IP else 'localhost'}:{8001 if PUBLIC_IP else 8000}/ws/dashboard/"
SEND_ORDER_TO_DASHBOARD_URL =  f"{BASE_URL}/fanaDashboard/receiveOrder/"
