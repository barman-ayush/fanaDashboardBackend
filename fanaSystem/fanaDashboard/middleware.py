from django.shortcuts import redirect
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from urllib.parse import urlencode

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(f"Got a request {request}")
        # Only apply to fanaDashboard URLs
        if not request.path.startswith('/fanaDashboard'):
            return self.get_response(request)

        # Retrieve JWT token from cookies
        token = request.COOKIES.get('jwt_token')

        # Verify token if present
        if token:
            try:
                AccessToken(token)  # Validate the JWT token
            except Exception:
                token = None  # Invalidate token if validation fails

        # Redirect to login if no valid token is found
        if not token:
            current_path = request.get_full_path()
            authenticator_login_url = f"{settings.AUTHENTICATOR_URL}/login/"
            
            # Avoid re-redirecting to login if already on login page
            if not current_path.startswith(authenticator_login_url):
                # Append `next` parameter only once
                query_string = urlencode({'next': current_path})
                return redirect(f"{authenticator_login_url}?{query_string}")
        
        # Proceed if token is valid
        return self.get_response(request)
