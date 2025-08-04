"""Base exception classes."""

import traceback
from typing import Any, Dict, Optional, Union
from rest_framework import status
from rest_framework.views import exception_handler
from .codes import ErrorCodes


class BaseAPIException(Exception):
    """Base API exception class."""
    
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'An error occurred.'
    default_code = ErrorCodes.INTERNAL_ERROR
    
    def __init__(
        self,
        detail: Optional[Union[str, Dict[str, Any]]] = None,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        extra_data: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize API exception.
        
        Args:
            detail: Error detail message or dict
            code: Error code
            status_code: HTTP status code
            extra_data: Additional error data
        """
        self.detail = detail or self.default_detail
        self.code = code or self.default_code
        self.status_code = status_code or self.status_code
        self.extra_data = extra_data or {}
        
        super().__init__(self.detail)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary."""
        error_dict = {
            'error': True,
            'code': self.code,
            'message': str(self.detail),
            'status_code': self.status_code,
        }
        
        if self.extra_data:
            error_dict.update(self.extra_data)
        
        return error_dict


class ValidationError(BaseAPIException):
    """Validation error exception."""
    
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Invalid input data.'
    default_code = ErrorCodes.VALIDATION_ERROR


class AuthenticationError(BaseAPIException):
    """Authentication error exception."""
    
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Authentication credentials were not provided or are invalid.'
    default_code = ErrorCodes.AUTHENTICATION_ERROR


class PermissionError(BaseAPIException):
    """Permission error exception."""
    
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = 'You do not have permission to perform this action.'
    default_code = ErrorCodes.PERMISSION_ERROR


class NotFoundError(BaseAPIException):
    """Not found error exception."""
    
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'The requested resource was not found.'
    default_code = ErrorCodes.NOT_FOUND_ERROR


class ConflictError(BaseAPIException):
    """Conflict error exception."""
    
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'The request could not be completed due to a conflict.'
    default_code = ErrorCodes.CONFLICT_ERROR


class RateLimitError(BaseAPIException):
    """Rate limit error exception."""
    
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = 'Too many requests. Please try again later.'
    default_code = ErrorCodes.RATE_LIMIT_ERROR


class ServiceUnavailableError(BaseAPIException):
    """Service unavailable error exception."""
    
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'Service temporarily unavailable. Please try again later.'
    default_code = ErrorCodes.SERVICE_UNAVAILABLE_ERROR


class BusinessLogicError(BaseAPIException):
    """Business logic error exception."""
    
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_detail = 'Business logic error occurred.'
    default_code = ErrorCodes.BUSINESS_LOGIC_ERROR


class ExternalServiceError(BaseAPIException):
    """External service error exception."""
    
    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = 'External service error occurred.'
    default_code = ErrorCodes.EXTERNAL_SERVICE_ERROR


class ConfigurationError(BaseAPIException):
    """Configuration error exception."""
    
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Configuration error occurred.'
    default_code = ErrorCodes.CONFIGURATION_ERROR


class TimeoutError(BaseAPIException):
    """Timeout error exception."""
    
    status_code = status.HTTP_408_REQUEST_TIMEOUT
    default_detail = 'Request timed out.'
    default_code = ErrorCodes.TIMEOUT_ERROR


class DatabaseError(BaseAPIException):
    """Database error exception."""
    
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Database error occurred.'
    default_code = ErrorCodes.DATABASE_ERROR


class CacheError(BaseAPIException):
    """Cache error exception."""
    
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Cache error occurred.'
    default_code = ErrorCodes.CACHE_ERROR


class SerializationError(BaseAPIException):
    """Serialization error exception."""
    
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Serialization error occurred.'
    default_code = ErrorCodes.SERIALIZATION_ERROR


class FileUploadError(BaseAPIException):
    """File upload error exception."""
    
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'File upload error occurred.'
    default_code = ErrorCodes.FILE_UPLOAD_ERROR


class QuotaExceededError(BaseAPIException):
    """Quota exceeded error exception."""
    
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = 'Quota exceeded.'
    default_code = ErrorCodes.QUOTA_EXCEEDED_ERROR


class MaintenanceModeError(BaseAPIException):
    """Maintenance mode error exception."""
    
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'Service is under maintenance. Please try again later.'
    default_code = ErrorCodes.MAINTENANCE_MODE_ERROR


# Exception mapping for automatic conversion
EXCEPTION_MAPPING = {
    'ValidationError': ValidationError,
    'AuthenticationError': AuthenticationError,
    'PermissionError': PermissionError,
    'NotFoundError': NotFoundError,
    'ConflictError': ConflictError,
    'RateLimitError': RateLimitError,
    'ServiceUnavailableError': ServiceUnavailableError,
    'BusinessLogicError': BusinessLogicError,
    'ExternalServiceError': ExternalServiceError,
    'ConfigurationError': ConfigurationError,
    'TimeoutError': TimeoutError,
    'DatabaseError': DatabaseError,
    'CacheError': CacheError,
    'SerializationError': SerializationError,
    'FileUploadError': FileUploadError,
    'QuotaExceededError': QuotaExceededError,
    'MaintenanceModeError': MaintenanceModeError,
}