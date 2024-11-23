import json
import requests
import time
from websocket import create_connection
from threading import Thread, Event

BASE_URL = "http://localhost:8000"
USERNAME = "valid_username"
PASSWORD = "valid_password"
ORDER_ID = "order_123"
DEVICE_ID = "device_123"
TABLE_ID = "table_1"

access_token = None
order_reflected = False
fana_call_reflected = False

stop_event = Event()


# Get JWT token
def get_jwt_token():
    global access_token
    print("[INFO] Getting JWT token...")
    response = requests.post(
        f"{BASE_URL}/fanaAuthenticator/api/token/",
        json={"username": USERNAME, "password": PASSWORD},
    )
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get("access")
        print("[INFO] JWT Token acquired:", tokens)
        return tokens
    else:
        print("[ERROR] Failed to acquire JWT token:", response.json())
        return None


# WebSocket Listener
def websocket_listener(stop_event):
    global order_reflected, fana_call_reflected, ws
    try:
        print("[INFO] WebSocket connection established.")
        while not stop_event.is_set():
            try:
                result = ws.recv()
                if not result.strip():
                    print("[INFO] Received an empty WebSocket message. Ignoring...")
                    continue

                print("[INFO] WebSocket event received:", result)
                try:
                    event = json.loads(result)
                except json.JSONDecodeError as e:
                    print(f"[ERROR] Failed to decode WebSocket message: {e}")
                    continue

                if event.get("message_type") == "order_update" and event.get("order_id") == ORDER_ID:
                    print("[INFO] Order reflected on dashboard.")
                    order_reflected = True

                if event.get("message_type") == "table_state" and event.get("table_id") == TABLE_ID:
                    print("[INFO] Fana call reflected on dashboard.")
                    fana_call_reflected = True
            except Exception as e:
                print(f"[ERROR] Error receiving WebSocket event: {e}")
                break
    finally:
        print("[INFO] WebSocket connection closing...")
        ws.close()



# Send Order
def send_order():
    global access_token
    print("[INFO] Sending order...")
    response = requests.post(
        f"{BASE_URL}/fanaDashboard/receiveOrder/",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "order_id": ORDER_ID,
            "order_details": {
                "items": [
                    {"name": "Burger", "cost": 100, "quantity": 2, "itemTotal": 200},
                    {"name": "Fries", "cost": 50, "quantity": 1, "itemTotal": 50},
                ],
                "totalAmount": 250,
            },
        },
    )
    print("[INFO] Send Order Response:", response.json())
    return response.status_code == 200 and response.json().get("status") == "success"


# Handle Fana Call
def handle_fana_call():
    global access_token
    print("[INFO] Sending fana call...")
    response = requests.post(
        f"{BASE_URL}/fanaDashboard/handleFanaCall/",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"table_id": TABLE_ID, "state": "calling", "time_taken": 1000},
    )
    print("[INFO] Handle Fana Call Response:", response.json())
    return response.status_code == 200 and response.json().get("status") == "success"


# Main Test Function
def test_sequence():
    global order_reflected, fana_call_reflected, ws, stop_event

    # Step 1: Get JWT Token
    tokens = get_jwt_token()
    if not tokens:
        print("[ERROR] Test failed: Unable to acquire JWT token.")
        print("Result: FAILED")
        return

    try:
        # Step 2: Connect to WebSocket
        print("[INFO] Connecting to WebSocket...")
        ws = create_connection(
            f"ws://{BASE_URL.split('//')[1]}/ws/dashboard/",
            header=[f"Authorization: Bearer {access_token}"],
        )
        print("[INFO] Connected to WebSocket.")

        # Step 3: Start WebSocket Listener in a separate thread
        listener_thread = Thread(target=websocket_listener, args=(stop_event,))
        listener_thread.start()

        # Step 4: Send Order
        if not send_order():
            print("[ERROR] Test failed: Order not sent successfully.")
            stop_event.set()
            listener_thread.join()
            print("Result: FAILED")
            return

        time.sleep(2)  # Allow some time for the dashboard to process

        # Step 5: Send Fana Call
        if not handle_fana_call():
            print("[ERROR] Test failed: Fana call not sent successfully.")
            stop_event.set()
            listener_thread.join()
            print("Result: FAILED")
            return

        time.sleep(2)  # Allow some time for WebSocket events to be received

        # Step 6: Validate WebSocket Events
        print("[INFO] Verifying WebSocket events...")
        if not order_reflected:
            print("[ERROR] Order not reflected on dashboard.")
        if not fana_call_reflected:
            print("[ERROR] Fana call not reflected on dashboard.")

        # Final Test Result
        if order_reflected and fana_call_reflected:
            print("Result: PASSED")
        else:
            print("Result: FAILED")

    except Exception as e:
        print(f"[ERROR] Test failed with exception: {e}")
        print("Result: FAILED")
    finally:
        # Signal the WebSocket listener thread to stop
        stop_event.set()
        if ws:
            ws.close()
        listener_thread.join()


# Run the Test
if __name__ == "__main__":
    test_sequence()
