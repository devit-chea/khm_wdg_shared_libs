import jwt
import logging
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from typing import Optional, Tuple
import os

logger = logging.getLogger(__name__)
User = get_user_model()


class JWTSettings:
    """
    Centralized JWT settings with defaults
    """

    def __init__(self):
        self.ALGORITHM = getattr(settings, "JWT_ALGORITHM", "RS256")
        self.PUBLIC_KEY_PATH = getattr(settings, "JWT_PUBLIC_KEY_PATH", None)
        self.PUBLIC_KEY = getattr(settings, "JWT_PUBLIC_KEY", None)
        self.PRIVATE_KEY_PATH = getattr(settings, "JWT_PRIVATE_KEY_PATH", None)
        self.PRIVATE_KEY = getattr(settings, "JWT_PRIVATE_KEY", None)
        self.ACCESS_TOKEN_LIFETIME = getattr(
            settings, "JWT_ACCESS_TOKEN_LIFETIME", 3600
        )  # 1 hour
        self.REFRESH_TOKEN_LIFETIME = getattr(
            settings, "JWT_REFRESH_TOKEN_LIFETIME", 604800
        )  # 7 days
        self.ISSUER = getattr(settings, "JWT_ISSUER", "microservice")
        self.AUDIENCE = getattr(settings, "JWT_AUDIENCE", "microservice-users")
        self.LEEWAY = getattr(settings, "JWT_LEEWAY", 10)  # seconds

    def get_public_key(self) -> str:
        """Get public key for token verification"""
        if self.PUBLIC_KEY:
            return self.PUBLIC_KEY
        elif self.PUBLIC_KEY_PATH and os.path.exists(self.PUBLIC_KEY_PATH):
            with open(self.PUBLIC_KEY_PATH, "r") as f:
                return f.read()
        else:
            raise ValueError("JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_PATH must be configured")

    def get_private_key(self) -> str:
        """Get private key for token signing"""
        if self.PRIVATE_KEY:
            return self.PRIVATE_KEY
        elif self.PRIVATE_KEY_PATH and os.path.exists(self.PRIVATE_KEY_PATH):
            with open(self.PRIVATE_KEY_PATH, "r") as f:
                return f.read()
        else:
            raise ValueError(
                "JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH must be configured"
            )


class JWTUser:
    """
    Custom user class for JWT authentication without database lookup
    """

    def __init__(self, user_id: str, email: str = None, username: str = None, **kwargs):
        self.id = user_id
        self.pk = user_id
        self.email = email
        self.username = username
        self.is_authenticated = True
        self.is_anonymous = False
        self.is_active = True

        # Store additional claims
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __str__(self):
        return f"JWTUser({self.id})"

    def has_perm(self, perm, obj=None):
        return True

    def has_perms(self, perm_list, obj=None):
        return True

    def has_module_perms(self, package_name):
        return True


class JWTTokenValidator:
    """
    JWT token validation utility
    """

    def __init__(self):
        self.jwt_settings = JWTSettings()

    def validate_token(self, token: str) -> dict:
        """
        Validate JWT token and return payload
        """
        try:
            public_key = self.jwt_settings.get_public_key()

            payload = jwt.decode(
                token,
                public_key,
                algorithms=[self.jwt_settings.ALGORITHM],
                audience=self.jwt_settings.AUDIENCE,
                issuer=self.jwt_settings.ISSUER,
                leeway=self.jwt_settings.LEEWAY,
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise AuthenticationFailed("Token validation failed")

    def extract_user_from_payload(self, payload: dict) -> JWTUser:
        """
        Extract user information from JWT payload
        """
        try:
            user_id = payload.get("user_id") or payload.get("sub")
            if not user_id:
                raise AuthenticationFailed("Token missing user identifier")

            email = payload.get("email")
            username = payload.get("username") or payload.get("preferred_username")

            # Extract additional claims
            additional_claims = {
                key: value
                for key, value in payload.items()
                if key
                not in [
                    "user_id",
                    "sub",
                    "email",
                    "username",
                    "preferred_username",
                    "exp",
                    "iat",
                    "iss",
                    "aud",
                    "jti",
                ]
            }

            return JWTUser(
                user_id=user_id, email=email, username=username, **additional_claims
            )

        except Exception as e:
            logger.error(f"Error extracting user from payload: {str(e)}")
            raise AuthenticationFailed("Invalid token payload")


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Django middleware for JWT authentication
    Processes JWT tokens from Authorization header
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.validator = JWTTokenValidator()

    def process_request(self, request):
        """
        Process incoming request for JWT token
        """
        # Skip authentication for certain paths
        skip_paths = getattr(
            settings,
            "JWT_SKIP_PATHS",
            [
                "/health/",
                "/docs/",
                "/admin/",
            ],
        )

        if any(request.path.startswith(path) for path in skip_paths):
            return None

        # Extract token from Authorization header
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            return None

        try:
            # Parse "Bearer <token>" format
            if not auth_header.startswith("Bearer "):
                return None

            token = auth_header.split(" ", 1)[1]

            # Validate token and extract user
            payload = self.validator.validate_token(token)
            user = self.validator.extract_user_from_payload(payload)

            # Attach user to request
            request.user = user
            request.jwt_payload = payload

        except AuthenticationFailed as e:
            return JsonResponse(
                {"error": "Authentication failed", "detail": str(e)},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            logger.error(f"JWT middleware error: {str(e)}")
            return JsonResponse(
                {"error": "Authentication error"}, status=status.HTTP_401_UNAUTHORIZED
            )

        return None


class JWTAuthentication(BaseAuthentication):
    """
    DRF Authentication class for JWT tokens
    Use this in REST framework settings or view-level authentication
    """

    def __init__(self):
        self.validator = JWTTokenValidator()

    def authenticate(self, request) -> Optional[Tuple[JWTUser, dict]]:
        """
        Authenticate request using JWT token
        Returns (user, token_payload) tuple or None
        """
        auth_header = self.get_auth_header(request)
        if not auth_header:
            return None

        try:
            token = self.get_token_from_header(auth_header)
            if not token:
                return None

            payload = self.validator.validate_token(token)
            user = self.validator.extract_user_from_payload(payload)

            return (user, payload)

        except AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(f"JWT authentication error: {str(e)}")
            raise AuthenticationFailed("Authentication failed")

    def get_auth_header(self, request) -> Optional[str]:
        """Extract authorization header"""
        return request.META.get("HTTP_AUTHORIZATION")

    def get_token_from_header(self, auth_header: str) -> Optional[str]:
        """Extract token from authorization header"""
        if not auth_header.startswith("Bearer "):
            return None

        try:
            return auth_header.split(" ", 1)[1]
        except IndexError:
            return None

    def authenticate_header(self, request) -> str:
        """Return WWW-Authenticate header for 401 responses"""
        return 'Bearer realm="api"'


class JWTTokenGenerator:
    """
    Utility class for generating JWT tokens
    Use this in authentication views or user creation
    """

    def __init__(self):
        self.jwt_settings = JWTSettings()

    def generate_access_token(self, user_data: dict) -> str:
        """
        Generate access token for user
        """
        import time

        now = int(time.time())
        payload = {
            "user_id": user_data.get("user_id"),
            "email": user_data.get("email"),
            "username": user_data.get("username"),
            "iat": now,
            "exp": now + self.jwt_settings.ACCESS_TOKEN_LIFETIME,
            "iss": self.jwt_settings.ISSUER,
            "aud": self.jwt_settings.AUDIENCE,
            "type": "access",
        }

        # Add custom claims
        custom_claims = user_data.get("custom_claims", {})
        payload.update(custom_claims)

        private_key = self.jwt_settings.get_private_key()

        return jwt.encode(payload, private_key, algorithm=self.jwt_settings.ALGORITHM)

    def generate_refresh_token(self, user_data: dict) -> str:
        """
        Generate refresh token for user
        """
        import time
        import uuid

        now = int(time.time())
        payload = {
            "user_id": user_data.get("user_id"),
            "iat": now,
            "exp": now + self.jwt_settings.REFRESH_TOKEN_LIFETIME,
            "iss": self.jwt_settings.ISSUER,
            "aud": self.jwt_settings.AUDIENCE,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
        }

        private_key = self.jwt_settings.get_private_key()

        return jwt.encode(payload, private_key, algorithm=self.jwt_settings.ALGORITHM)


class JWTPermissionMixin:
    """
    Mixin for views that require JWT authentication
    """

    def dispatch(self, request, *args, **kwargs):
        """
        Ensure user is authenticated via JWT
        """
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return JsonResponse(
                {"error": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return super().dispatch(request, *args, **kwargs)
