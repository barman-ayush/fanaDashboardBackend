import json
import hashlib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from django.conf import settings

# Constants
FANA_DASHBOARD_URL = settings.SEND_ORDER_TO_DASHBOARD_URL  # Endpoint to forward customer orders


# --- UTILITY FUNCTIONS ---
def load_registered_device_ids():
    """
    Load registered device IDs from a JSON file.
    """
    try:
        with open("registered_devices.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = {"device_ids": []}
    return data["device_ids"]


def save_registered_device_ids(device_ids):
    """
    Save registered device IDs to a JSON file.
    """
    with open("registered_devices.json", "w") as file:
        json.dump({"device_ids": device_ids}, file, indent=4)


def generate_custom_user_id(username):
    """
    Generate a unique integer user_id by hashing the username.
    """
    hash_object = hashlib.sha256(username.encode())
    return int(hash_object.hexdigest()[:8], 16)  # Use the first 8 characters of the hash


def generate_tokens(username, app):
    """
    Generate JWT tokens with custom claims.
    """
    refresh = RefreshToken()
    refresh["app"] = app
    refresh["username"] = username
    refresh["user_id"] = 1  # Dummy user_id; replace with `generate_custom_user_id(username)` if needed

    print("Generated Refresh Token:", str(refresh))
    print("Generated Access Token:", str(refresh.access_token))

    return {
        'status': 'success',
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


# --- AUTHENTICATION ENDPOINT ---
class CustomTokenObtainPairView(APIView):
    """
    Generate JWT tokens after validating credentials.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        app = request.data.get("app")

        # Validate credentials
        if validate_credentials(username, password):
            print("[INFO] Credentials validated successfully.")
            return Response(generate_tokens(username=username, app=app))
        else:
            return Response({"status": "error", "detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


def validate_credentials(username, password):
    """
    Validate credentials. Replace this with actual logic.
    """
    return username == "valid_username" and password == "valid_password"


# --- DEVICE MANAGEMENT ENDPOINTS ---
class AddDeviceView(APIView):
    """
    Add a new device ID.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        print(f"[DEBUG] AddDeviceView invoked with request: {request}")
        device_id = request.data.get("device_id")
        if not device_id:
            return Response({"status": "error", "message": "Device ID is missing"}, status=status.HTTP_400_BAD_REQUEST)

        device_ids = load_registered_device_ids()
        if device_id in device_ids:
            return Response({"status": "error", "message": "Device ID already exists"}, status=status.HTTP_400_BAD_REQUEST)

        device_ids.append(device_id)
        save_registered_device_ids(device_ids)
        return Response({"status": "success", "message": "Device ID added successfully"}, status=status.HTTP_201_CREATED)


class RemoveDeviceView(APIView):
    """
    Remove an existing device ID.
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        print(f"[DEBUG] RemoveDeviceView invoked with request: {request}")
        device_id = request.data.get("device_id")
        if not device_id:
            return Response({"status": "error", "message": "Device ID is missing"}, status=status.HTTP_400_BAD_REQUEST)

        device_ids = load_registered_device_ids()
        if device_id not in device_ids:
            return Response({"status": "error", "message": "Device ID not found"}, status=status.HTTP_404_NOT_FOUND)

        device_ids.remove(device_id)
        save_registered_device_ids(device_ids)
        return Response({"status": "success", "message": "Device ID removed successfully"}, status=status.HTTP_200_OK)


# --- ORDER MANAGEMENT ENDPOINT ---
@csrf_exempt
def handle_customer_order(request):
    """
    Receive customer orders and forward them to the dashboard.
    """
    if request.method == 'POST':
        print("Got a request", order_data)
        order_data = json.loads(request.body)
        try:
            response = requests.post(FANA_DASHBOARD_URL, json=order_data)
            response.raise_for_status()  # Check for HTTP errors
            return JsonResponse({'status': 'success', 'message': 'Order forwarded to fanaDashboard'})
        except requests.RequestException as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)
