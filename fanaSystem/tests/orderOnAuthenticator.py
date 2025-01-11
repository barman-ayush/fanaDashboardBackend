import requests
import os
import common as settings

BASE_URL = f"{settings.BASE_URL}/fanaAuthenticator/api"

# Set the URLs for fanaAuthenticator and fanaDashboard from environment variables
FANA_AUTHENTICATOR_URL = os.getenv("FANA_AUTHENTICATOR_URL", "http://localhost:8000/fanaAuthenticator/handle_customer_order/")
FANA_DASHBOARD_URL = os.getenv("FANA_DASHBOARD_URL", "http://localhost:8000/fanaDashboard/receiveOrder/")

# Sample order data to send
order_data = {
    "order_id": "12345",
    "order_details": "Product XYZ, Quantity: 2"
}

order_data2 = {
    "order_id": "123456",
    "order_details": "Product XYZ, Quantity: 2"
}

# Function to simulate the customer placing an order on fanaAuthenticator
def send_order_to_fana_authenticator(order_data):
    try:
        print("Sending order to fanaAuthenticator...")
        response = requests.post(FANA_AUTHENTICATOR_URL, json=order_data)
        response.raise_for_status()
        print("Order sent to fanaAuthenticator successfully:", response.json())
    except requests.RequestException as e:
        print("Error sending order to fanaAuthenticator:", e)

# Function to simulate fanaAuthenticator forwarding the order to fanaDashboard
def forward_order_to_fana_dashboard(order_data):
    try:
        print("Forwarding order to fanaDashboard...")
        response = requests.post(FANA_DASHBOARD_URL, json=order_data)
        response.raise_for_status()
        print("Order forwarded to fanaDashboard successfully:", response.json())
    except requests.RequestException as e:
        print("Error forwarding order to fanaDashboard:", e)

# Main function to test the end-to-end flow
def test_order_flow():
    # Step 1: Send order to fanaAuthenticator
    # send_order_to_fana_authenticator(order_data)
    
    # Step 2: Forward the order directly to fanaDashboard (for testing purposes)
    # 
    forward_order_to_fana_dashboard(order_data)
    forward_order_to_fana_dashboard(order_data2)

if __name__ == "__main__":
    test_order_flow()
