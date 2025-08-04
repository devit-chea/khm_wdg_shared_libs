"""Exception handlers for consistent error responses."""

import logging
import traceback
from typing import Any, Dict, Optional
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.exceptions import (
    ValidationError as DRFValidationError,
    AuthenticationFailed,
    PermissionDenied,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    UnsupportedMediaType,
    Throttled,
    ParseError,
)

from .base import (
    BaseAPIException,
    ValidationError,
    AuthenticationError,
    PermissionError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
    DatabaseError,
)
from .codes import ErrorCodes, get_error_category

logger = logging.getLogger(__name__)


def _get_client_ip(request) -> Optional[str]:
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _log_exception(exc, request, view):
    """Log exception details."""
    # Prepare log context
    log_context = {
        'exception_type': exc.__class__.__name__,
        'exception_message': str(exc),
    }
    
    # Add request info
    if request:
        log_context.update({
            'method': request.method,
            'path': request.path,
            'user': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
            'ip_address': _get_client_ip(request),
        })
    
    # Add view info
    if view:
        log_context['view'] = view.__class__.__name__
    
    # Log based on exception type
    if isinstance(exc, BaseAPIException):
        if exc.status_code >= 500:
            logger.error(
                f"API Error: {exc.code}",
                extra=log_context,
                exc_info=True
            )
        else:
            logger.warning(
                f"API Error: {exc.code}",
                extra=log_context
            )
    elif isinstance(exc, (DRFValidationError, DjangoValidationError)):
        logger.info(
            "Validation Error",
            extra=log_context
        )
    elif isinstance(exc, (AuthenticationFailed, PermissionDenied)):
        logger.warning(
            "Security Error",
            extra=log_context
        )
    else:
        logger.error(
            "Unexpected Error",
            extra=log_context,
            exc_info=True
        )


def _handle_base_api_exception(exc: BaseAPIException, request) -> Response:
    """Handle BaseAPIException instances."""
    error_data = {
        'error': True,
        'code': exc.code,
        'message': str(exc.detail),
        'category': get_error_category(exc.code),
    }
    
    # Add extra data if available
    if exc.extra_data:
        error_data.update(exc.extra_data)
    
    # Add debug info in development
    if settings.DEBUG:
        error_data['debug'] = {
            'exception_type': exc.__class__.__name__,
            'traceback': traceback.format_exc(),
        }
    
    # Add request ID if available
    if hasattr(request, 'id'):
        error_data['request_id'] = request.id
    
    return Response(error_data, status=exc.status_code)


def _handle_drf_exception(exc, response, request) -> Response:
    """Handle DRF exceptions."""
    # Map DRF exceptions to our error codes
    error_code_mapping = {
        DRFValidationError: ErrorCodes.VALIDATION_ERROR,
        AuthenticationFailed: ErrorCodes.AUTHENTICATION_ERROR,
        PermissionDenied: ErrorCodes.PERMISSION_ERROR,
        NotFound: ErrorCodes.NOT_FOUND_ERROR,
        MethodNotAllowed: ErrorCodes.METHOD_NOT_ALLOWED,
        NotAcceptable: ErrorCodes.INVALID_FORMAT,
        UnsupportedMediaType: ErrorCodes.INVALID_FORMAT,
        Throttled: ErrorCodes.RATE_LIMIT_ERROR,
        ParseError: ErrorCodes.INVALID_INPUT,
    }
    
    error_code = error_code_mapping.get(type(exc), ErrorCodes.UNKNOWN_ERROR)
    
    # Handle validation errors specially to preserve field-level errors
    if isinstance(exc, DRFValidationError):
        error_data = {
            'error': True,
            'code': error_code,
            'message': 'Validation failed',
            'category': get_error_category(error_code),
            'details': response.data,
        }
    else:
        # Get error message
        if hasattr(exc, 'detail'):
            if isinstance(exc.detail, dict):
                message = str(exc.detail.get('detail', exc.detail))
            elif isinstance(exc.detail, list) and exc.detail:
                message = str(exc.detail[0])
            else:
                message = str(exc.detail)
        else:
            message = str(exc)
        
        error_data = {
            'error': True,
            'code': error_code,
            'message': message,
            'category': get_error_category(error_code),
        }
    
    # Add throttling info for rate limit errors
    if isinstance(exc, Throttled):
        error_data['retry_after'] = exc.wait
    
    # Add debug info in development
    if settings.DEBUG:
        error_data['debug'] = {
            'exception_type': exc.__class__.__name__,
            'original_response': response.data,
        }
    
    # Add request ID if available
    if hasattr(request, 'id'):
        error_data['request_id'] = request.id
    
    return Response(error_data, status=response.status_code)


def _handle_django_exception(exc, request) -> Optional[Response]:
    """Handle Django exceptions."""
    if isinstance(exc, Http404):
        error_data = {
            'error': True,
            'code': ErrorCodes.NOT_FOUND_ERROR,
            'message': 'The requested resource was not found.',
            'category': get_error_category(ErrorCodes.NOT_FOUND_ERROR),
        }
        
        if settings.DEBUG:
            error_data['debug'] = {
                'exception_type': exc.__class__.__name__,
                'original_message': str(exc),
            }
        
        return Response(error_data, status=status.HTTP_404_NOT_FOUND)
    
    if isinstance(exc, DjangoValidationError):
        error_data = {
            'error': True,
            'code': ErrorCodes.VALIDATION_ERROR,
            'message': 'Validation failed',
            'category': get_error_category(ErrorCodes.VALIDATION_ERROR),
        }
        
        # Add validation details
        if hasattr(exc, 'message_dict'):
            error_data['details'] = exc.message_dict
        elif hasattr(exc, 'messages'):
            error_data['details'] = exc.messages
        else:
            error_data['details'] = str(exc)
        
        if settings.DEBUG:
            error_data['debug'] = {
                'exception_type': exc.__class__.__name__,
                'original_message': str(exc),
            }
        
        return Response(error_data, status=status.HTTP_400_BAD_REQUEST)
    
    return None


def _handle_unexpected_exception(exc, request) -> Response:
    """Handle unexpected exceptions."""
    error_data = {
        'error': True,
        'code': ErrorCodes.INTERNAL_ERROR,
        'message': 'An unexpected error occurred.',
        'category': get_error_category(ErrorCodes.INTERNAL_ERROR),
    }
    
    # Add debug info in development
    if settings.DEBUG:
        error_data['debug'] = {
            'exception_type': exc.__class__.__name__,
            'original_message': str(exc),
            'traceback': traceback.format_exc(),
        }
    
    # Add request ID if available
    if hasattr(request, 'id'):
        error_data['request_id'] = request.id
    
    return Response(error_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that provides consistent error responses.
    
    Args:
        exc: Exception instance
        context: Context dictionary containing request and view info
    
    Returns:
        Response object with error details
    """
    # Get the standard error response first
    response = drf_exception_handler(exc, context)
    
    # Get request info for logging
    request = context.get('request')
    view = context.get('view')
    
    # Log the exception
    _log_exception(exc, request, view)
    
    # Handle our custom exceptions
    if isinstance(exc, BaseAPIException):
        return _handle_base_api_exception(exc, request)
    
    # Handle DRF exceptions
    if response is not None:
        return _handle_drf_exception(exc, response, request)
    
    # Handle Django exceptions
    django_response = _handle_django_exception(exc, request)
    if django_response:
        return django_response
    
    # Handle unexpected exceptions
    return _handle_unexpected_exception(exc, request)


def _handle_base_api_exception(exc: BaseAPIException, request) -> Response:
    """Handle BaseAPIException instances."""
    error_data = {
        'error': True,
        'code': exc.code,
        'message': str(exc.detail),
        'category': get_error_category(exc.code),
    }
    
    # Add extra data if available
    if exc.extra_data:
        error_data.update(exc.extra_data)
    
    # Add debug info in development
    if settings.DEBUG:
        error_data['debug'] = {
            'exception_type': exc.__class__.__name__,
            'traceback': traceback.format_exc(),
        }
    
    # Add request ID if available
    if hasattr(request, 'id'):
        error_data['request_id'] = request.id
    
    return Response(error_data, status=exc.status_code)


def _handle_drf_exception(exc, response, request) -> Response:
    """Handle DRF exceptions."""
    # Map DRF exceptions to our error codes
    error_code_mapping = {
        DRFValidationError: ErrorCodes.VALIDATION_ERROR,
        AuthenticationFailed: ErrorCodes.AUTHENTICATION_ERROR,
        PermissionDenied: ErrorCodes.PERMISSION_ERROR,
        NotFound: ErrorCodes.NOT_FOUND_ERROR,
        MethodNotAllowed: ErrorCodes.METHOD_NOT_ALLOWED,
        NotAcceptable: ErrorCodes.INVALID_FORMAT,
        UnsupportedMediaType: ErrorCodes.INVALID_FORMAT,
        Throttled: ErrorCodes.RATE_LIMIT_ERROR,
        ParseError: ErrorCodes.INVALID_INPUT,
    }
    
    error_code = error_code_mapping.get(type(exc), ErrorCodes.UNKNOWN_ERROR)
    
    # Handle validation errors specially to preserve field-level errors
    if isinstance(exc, DRFValidationError):
        error_data = {
            'error': True,
            'code': error_code,
            'message': 'Validation failed',
            'category': get_error_category(error_code),
            'details': response.data,
        }
    else:
        # Get error message
        if hasattr(exc, 'detail'):
            if isinstance(exc.detail, dict):
                message = str(exc.detail.get('detail', exc.detail))
            elif isinstance(exc.detail, list) and exc.detail:
                message = str(exc.detail[0])
            else:
                message = str(exc.detail)
        else:
            message = str(exc)
        
        error_data = {
            'error': True,
            'code': error_code,
            'message': message,
            'category': get_error_category(error_code),
        }
    
    # Add throttling info for rate limit errors
    if isinstance(exc, Throttled):
        error_data['retry_after'] = exc.wait
    
    # Add debug info in development
    if settings.DEBUG:
        error_data['debug'] = {
            'exception_type': exc.__class__.__name__,
            'original_response': response.data,
        }
    
    # Add request ID if available
    if hasattr(request, 'id'):
        error_data['request_id'] = request.id
    
    return Response(error_data, status=response.status_code)


def _handle_django_exception(exc, request) -> Optional[Response]:
    """Handle Django exceptions."""
    if isinstance(exc, Http404):
        error_data = {
            'error': True,
            'code': ErrorCodes.NOT_FOUND_ERROR,
            'message': 'The requested resource was not found.',
            'category': get_error_category(ErrorCodes.NOT_FOUND_ERROR),
        }
        
        if settings.DEBUG:
            error_data['debug'] = {
                'exception_type': exc.__class__.__name__,
                'original_message': str(exc),
            }
        
        return Response(error_data, status=status.HTTP_404_NOT_FOUND)
    
    if isinstance(exc, DjangoValidationError):
        error_data = {
            'error': True,
            'code': ErrorCodes.VALIDATION_ERROR,
            'message': 'Validation failed',
            'category': get_error_category(ErrorCodes.VALIDATION_ERROR),
        }
        
        # Add validation details
        if hasattr(exc, 'message_dict'):
            error_data['details'] = exc.message_dict
        elif hasattr(exc, 'messages'):
            error_data['details'] = exc.messages
        else:
            error_data['details'] = str(exc)