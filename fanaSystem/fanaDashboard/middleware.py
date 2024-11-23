from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from channels.middleware import BaseMiddleware
from jwt import decode as jwt_decode, ExpiredSignatureError, InvalidTokenError
from django.conf import settings

class JWTAuthenticationMiddleware:
    """
    Middleware for authenticating HTTP requests using JWT.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        """
        Authenticate HTTP requests.
        """
        print(f"[DEBUG] JWTAuthenticationMiddleware invoked for HTTP path: {request.path}")
        token = self._get_token_from_request(request)
        if token:
            try:
                decoded_token = jwt_decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                user = self.get_user_from_token(decoded_token)
                request.user = user  # Attach user to the request
                print(f"[DEBUG] Token validated successfully for user: {user}.")
            except (ExpiredSignatureError, InvalidTokenError) as e:
                print(f"[ERROR] Token validation failed: {e}")
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

        return self.get_response(request)

    def _get_token_from_request(self, request):
        """
        Extract JWT token from cookies or Authorization header for HTTP requests.
        """
        token = request.COOKIES.get('jwt_token')
        if not token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split('Bearer ')[-1]
        return token

    def get_user_from_token(self, decoded_token):
        """
        Retrieve or create a user based on the token.
        """
        User = get_user_model()
        username = decoded_token.get("username")
        if username:
            user, created = User.objects.get_or_create(username=username)
            return user
        return AnonymousUser()

from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken
from jwt import decode as jwt_decode, ExpiredSignatureError, InvalidTokenError
from django.conf import settings


class WebSocketJWTAuthenticationMiddleware(BaseMiddleware):
    """
    Middleware for authenticating WebSocket requests using JWT.
    """

    async def __call__(self, scope, receive, send):
        """
        Handle the WebSocket connection lifecycle.
        """
        print("[DEBUG] WebSocketJWTAuthenticationMiddleware invoked.")
        token = self._get_token_from_scope(scope)
        if token:
            try:
                decoded_token = jwt_decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                print("Got the tocken ", decoded_token)
                user = self.get_user_from_token(decoded_token)
                scope["user"] = user
                print(f"[DEBUG] WebSocket token validated for user: {user}.")
            except ExpiredSignatureError:
                print("[ERROR] WebSocket token has expired.")
                scope["user"] = AnonymousUser()
            except InvalidTokenError as e:
                print(f"[ERROR] Invalid WebSocket token: {e}")
                scope["user"] = AnonymousUser()
        else:
            print("[INFO] No WebSocket token found. Assigning AnonymousUser.")
            scope["user"] = AnonymousUser()

        return await super().__call__(scope, receive, send)

    def _get_token_from_scope(self, scope):
        """
        Extract JWT token from headers or cookies for WebSocket requests.
        """
        headers = dict(scope.get("headers", []))
        token = None

        # Check Authorization header
        if b"authorization" in headers:
            auth_header = headers[b"authorization"].decode("utf-8")
            if auth_header.startswith("Bearer "):
                token = auth_header.split("Bearer ")[-1]

        # Check cookies
        if not token and b"cookie" in headers:
            cookie_header = headers[b"cookie"].decode("utf-8")
            for cookie in cookie_header.split("; "):
                if cookie.startswith("jwt_token="):
                    token = cookie.split("=")[-1]
        return token

    def get_user_from_token(self, decoded_token):
        """
        Retrieve or create a user based on the token for WebSocket.
        """
        username = decoded_token.get("username")
        return username
