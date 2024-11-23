from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(f"[DEBUG] JWTAuthenticationMiddleware invoked for path: {request.path}")

        token = self._get_token_from_request(request)
        print(f"[DEBUG] Extracted token: {token}")

        if token:
            try:
                decoded_token = AccessToken(token)  # Validate the JWT token
                user = self.get_user_from_token(decoded_token)
                request.user = user  # Set the user on the request
                print(f"[DEBUG] Token validation successful. User: {user}")
            except Exception as e:
                print(f"[ERROR] Token validation failed: {e}")
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

        return self.get_response(request)

    def _get_token_from_request(self, request):
        """
        Extract JWT token from cookies or Authorization header.
        """
        token = request.COOKIES.get('jwt_token')
        if not token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split('Bearer ')[-1]
        return token

    def get_user_from_token(self, decoded_token):
        User = get_user_model()
        username = decoded_token.get("username")
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return AnonymousUser()