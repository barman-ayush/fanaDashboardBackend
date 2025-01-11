import requests
import common as settings
BASE_URL = f"{settings.BASE_URL}/fanaAuthenticator/api"
USERNAME = "valid_username"
PASSWORD = "valid_password"
DEVICE_ID = "test_device_123"

# Function to get a JWT token
def get_jwt_token(username, password, device_id):
    url = f"{BASE_URL}/token/"
    print(f"Doing a post request on {url}")
    response = requests.post(url, json={
        "username": username,
        "password": password,
        "device_id": device_id
    })
    if response.status_code == 200:
        tokens = response.json()
        print("JWT Token acquired:", tokens)
        return tokens["access"]
    else:
        print("Failed to acquire JWT token:", response.json())
        return None

# Function to add a device with JWT token in headers
def add_device(device_id, token):
    url = f"{BASE_URL}/add_device/"
    print(f"Doing a post request on {url}")

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(url, json={"device_id": device_id}, headers=headers)
    print("Add Device Response:", response.json())

# Function to remove a device with JWT token in headers
def remove_device(device_id, token):
    url = f"{BASE_URL}/remove_device/"
    print(f"Doing a delete request on {url}")

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(url, json={"device_id": device_id}, headers=headers)
    print("Remove Device Response:", response.json())

# Main test sequence
def test_sequence():
    # Step 1: Get JWT Token
    print("Getting JWT token...")
    token = get_jwt_token(USERNAME, PASSWORD, DEVICE_ID)
    if not token:
        print("Cannot proceed without a valid JWT token.")
        return

    # Step 2: Add a device
    print("\nAdding device...")
    add_device(DEVICE_ID, token)

    # Step 3: Attempt to add the same device again
    print("\nAttempting to add the same device again (expecting duplicate error)...")
    add_device(DEVICE_ID, token)

    # Step 4: Remove the device
    print("\nRemoving device...")
    remove_device(DEVICE_ID, token)

    # Step 5: Attempt to remove the same device again
    print("\nAttempting to remove the same device again (expecting not found error)...")
    remove_device(DEVICE_ID, token)

# Run the test sequence
test_sequence()
