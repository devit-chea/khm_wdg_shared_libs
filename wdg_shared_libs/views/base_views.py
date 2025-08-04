"""Base view classes for consistent API behavior."""

import logging
from typing import Any, Dict, List, Optional, Type
from django.db.models import QuerySet
from django.core.cache import cache
from rest_framework import status, viewsets, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django.utils import timezone

from ..exceptions.base import ValidationError, NotFoundError
from ..schemas.base_serializers import (
    BaseResponseSerializer,
    PaginatedResponseSerializer,
    SingleItemResponseSerializer,
    BulkOperationResponseSerializer
)
from ..utils.common import generate_uuid4

logger = logging.getLogger(__name__)


class StandardResultPagination(PageNumberPagination):
    """Standard pagination class."""
    
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    
    def get_paginated_response(self, data):
        """Return paginated response with metadata."""
        return Response({
            'success': True,
            'message': 'Data retrieved successfully',
            'timestamp': timezone.now(),
            'request_id': generate_uuid4(),
            'data': data,
            'pagination': {
                'count': self.page.paginator.count,
                'page': self.page.number,
                'pages': self.page.paginator.num_pages,
                'page_size': self.get_page_size(self.request),
                'has_next': self.page.has_next(),
                'has_previous': self.page.has_previous(),
                'next_page': self.page.next_page_number() if self.page.has_next() else None,
                'previous_page': self.page.previous_page_number() if self.page.has_previous() else None,
            }
        })


class BaseAPIView(generics.GenericAPIView):
    """Base API view with common functionality."""
    
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultPagination
    
    def __init__(self, *args, **kwargs):
        """Initialize view with request ID."""
        super().__init__(*args, **kwargs)
        self.request_id = generate_uuid4()
    
    def initial(self, request, *args, **kwargs):
        """Perform initial setup."""
        super().initial(request, *args, **kwargs)
        
        # Set request ID
        request.id = self.request_id
        
        # Log request
        self.log_request(request)
    
    def log_request(self, request: Request):
        """Log incoming request."""
        logger.info(
            f"API Request: {request.method} {request.path}",
            extra={
                'request_id': self.request_id,
                'method': request.method,
                'path': request.path,
                'user': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'ip_address': self.get_client_ip(request),
            }
        )
    
    def get_client_ip(self, request: Request) -> Optional[str]:
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def create_response(
        self,
        data: Any = None,
        message: str = "Operation completed successfully",
        status_code: int = status.HTTP_200_OK,
        extra_data: Optional[Dict] = None
    ) -> Response:
        """Create standardized response."""
        response_data = {
            'success': True,
            'message': message,
            'timestamp': timezone.now(),
            'request_id': self.request_id,
        }
        
        if data is not None:
            response_data['data'] = data
        
        if extra_data:
            response_data.update(extra_data)
        
        return Response(response_data, status=status_code)
    
    def handle_exception(self, exc):
        """Handle exceptions with logging."""
        logger.error(
            f"Exception in view: {exc}",
            extra={
                'request_id': self.request_id,
                'exception_type': exc.__class__.__name__,
                'view': self.__class__.__name__,
            },
            exc_info=True
        )
        return super().handle_exception(exc)


class BaseModelViewSet(viewsets.ModelViewSet):
    """Base model viewset with enhanced functionality."""
    
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultPagination
    lookup_field = 'id'
    
    # Cache settings
    cache_timeout = 300  # 5 minutes
    cache_key_prefix = None
    
    def __init__(self, *args, **kwargs):
        """Initialize viewset."""
        super().__init__(*args, **kwargs)
        self.request_id = generate_uuid4()
    
    def initial(self, request, *args, **kwargs):
        """Perform initial setup."""
        super().initial(request, *args, **kwargs)
        request.id = self.request_id
        self.log_request(request)
    
    def log_request(self, request: Request):
        """Log incoming request."""
        logger.info(
            f"API Request: {request.method} {request.path}",
            extra={
                'request_id': self.request_id,
                'method': request.method,
                'path': request.path,
                'user': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'view': self.__class__.__name__,
                'action': getattr(self, 'action', None),
            }
        )
    
    def get_queryset(self):
        """Get filtered queryset."""
        queryset = super().get_queryset()
        
        # Apply soft delete filter if model supports it
        if hasattr(self.queryset.model, 'is_deleted'):
            queryset = queryset.filter(is_deleted=False)
        
        return queryset
    
    def get_cache_key(self, suffix: str = '') -> str:
        """Generate cache key."""
        prefix = self.cache_key_prefix or f"{self.__class__.__name__}"
        return f"{prefix}:{suffix}" if suffix else prefix
    
    def get_cached_data(self, key: str) -> Any:
        """Get data from cache."""
        return cache.get(key)
    
    def set_cached_data(self, key: str, data: Any, timeout: Optional[int] = None) -> None:
        """Set data in cache."""
        cache.set(key, data, timeout or self.cache_timeout)
    
    def invalidate_cache(self, pattern: str = None) -> None:
        """Invalidate cache entries."""
        if pattern:
            # This would require a more sophisticated cache backend
            # For now, we'll just delete specific keys
            cache.delete(pattern)
    
    def perform_create(self, serializer):
        """Perform create with audit trail."""
        if hasattr(serializer.Meta.model, 'created_by'):
            serializer.save(created_by=self.request.user)
        else:
            serializer.save()
    
    def perform_update(self, serializer):
        """Perform update with audit trail."""
        if hasattr(serializer.Meta.model, 'updated_by'):
            serializer.save(updated_by=self.request.user)
        else:
            serializer.save()
    
    def perform_destroy(self, instance):
        """Perform soft delete if supported, otherwise hard delete."""
        if hasattr(instance, 'delete') and hasattr(instance, 'is_deleted'):
            # Soft delete
            instance.delete(user=self.request.user)
        else:
            # Hard delete
            instance.delete()
    
    def create(self, request, *args, **kwargs):
        """Create instance with enhanced response."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        headers = self.get_success_headers(serializer.data)
        return self.create_response(
            data=serializer.data,
            message="Resource created successfully",
            status_code=status.HTTP_201_CREATED,
            headers=headers
        )
    
    def update(self, request, *args, **kwargs):
        """Update instance with enhanced response."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return self.create_response(
            data=serializer.data,
            message="Resource updated successfully"
        )
    
    def destroy(self, request, *args, **kwargs):
        """Delete instance with enhanced response."""
        instance = self.get_object()
        self.perform_destroy(instance)
        
        return self.create_response(
            message="Resource deleted successfully",
            status_code=status.HTTP_204_NO_CONTENT
        )
    
    def list(self, request, *args, **kwargs):
        """List instances with caching support."""
        cache_key = self.get_cache_key(f"list:{request.GET.urlencode()}")
        cached_response = self.get_cached_data(cache_key)
        
        if cached_response and not request.query_params.get('no_cache'):
            return Response(cached_response)
        
        queryset = self.filter_queryset(self.get_queryset())
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            response = self.get_paginated_response(serializer.data)
            
            # Cache the response
            self.set_cached_data(cache_key, response.data)
            return response
        
        serializer = self.get_serializer(queryset, many=True)
        response_data = self.create_response(
            data=serializer.data,
            message="Resources retrieved successfully"
        ).data
        
        # Cache the response
        self.set_cached_data(cache_key, response_data)
        return Response(response_data)
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve instance with caching support."""
        cache_key = self.get_cache_key(f"detail:{kwargs.get(self.lookup_field)}")
        cached_response = self.get_cached_data(cache_key)
        
        if cached_response and not request.query_params.get('no_cache'):
            return Response(cached_response)
        
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        response_data = self.create_response(
            data=serializer.data,
            message="Resource retrieved successfully"
        ).data
        
        # Cache the response
        self.set_cached_data(cache_key, response_data)
        return Response(response_data)
    
    def create_response(
        self,
        data: Any = None,
        message: str = "Operation completed successfully",
        status_code: int = status.HTTP_200_OK,
        headers: Optional[Dict] = None
    ) -> Response:
        """Create standardized response."""
        response_data = {
            'success': True,
            'message': message,
            'timestamp': timezone.now(),
            'request_id': self.request_id,
        }
        
        if data is not None:
            response_data['data'] = data
        
        return Response(response_data, status=status_code, headers=headers)
    
    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        """Bulk create multiple instances."""
        if not isinstance(request.data, list):
            raise ValidationError("Expected a list of objects")
        
        serializer = self.get_serializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)
        
        instances = []
        errors = []
        
        for i, item_data in enumerate(request.data):
            try:
                item_serializer = self.get_serializer(data=item_data)
                item_serializer.is_valid(raise_exception=True)
                self.perform_create(item_serializer)
                instances.append(item_serializer.data)
            except Exception as e:
                errors.append({
                    'index': i,
                    'data': item_data,
                    'error': str(e)
                })
        
        response_data = {
            'total': len(request.data),
            'successful': len(instances),
            'failed': len(errors),
            'data': instances,
        }
        
        if errors:
            response_data['errors'] = errors
        
        return self.create_response(
            data=response_data,
            message=f"Bulk create completed: {len(instances)} successful, {len(errors)} failed",
            status_code=status.HTTP_201_CREATED
        )
    
    @action(detail=False, methods=['patch'])
    def bulk_update(self, request):
        """Bulk update multiple instances."""
        if not isinstance(request.data, list):
            raise ValidationError("Expected a list of objects")
        
        instances = []
        errors = []
        
        for i, item_data in enumerate(request.data):
            try:
                if 'id' not in item_data:
                    raise ValidationError("ID is required for updates")
                
                instance = self.get_queryset().get(id=item_data['id'])
                item_serializer = self.get_serializer(
                    instance, 
                    data=item_data, 
                    partial=True
                )
                item_serializer.is_valid(raise_exception=True)
                self.perform_update(item_serializer)
                instances.append(item_serializer.data)
            except Exception as e:
                errors.append({
                    'index': i,
                    'data': item_data,
                    'error': str(e)
                })
        
        response_data = {
            'total': len(request.data),
            'successful': len(instances),
            'failed': len(errors),
            'data': instances,
        }
        
        if errors:
            response_data['errors'] = errors
        
        return self.create_response(
            data=response_data,
            message=f"Bulk update completed: {len(instances)} successful, {len(errors)} failed"
        )
    
    @action(detail=False, methods=['delete'])
    def bulk_delete(self, request):
        """Bulk delete multiple instances."""
        ids = request.data.get('ids', [])
        if not ids:
            raise ValidationError("List of IDs is required")
        
        deleted_count = 0
        errors = []
        
        for item_id in ids:
            try:
                instance = self.get_queryset().get(id=item_id)
                self.perform_destroy(instance)
                deleted_count += 1
            except Exception as e:
                errors.append({
                    'id': item_id,
                    'error': str(e)
                })
        
        response_data = {
            'total': len(ids),
            'successful': deleted_count,
            'failed': len(errors),
        }
        
        if errors:
            response_data['errors'] = errors
        
        return self.create_response(
            data=response_data,
            message=f"Bulk delete completed: {deleted_count} successful, {len(errors)} failed",
            status_code=status.HTTP_204_NO_CONTENT
        )


class ReadOnlyModelViewSet(BaseModelViewSet):
    """Read-only model viewset."""
    
    http_method_names = ['get', 'head', 'options']
    
    def create(self, request, *args, **kwargs):
        """Disabled create method."""
        return Response(
            {'error': 'Create operation not allowed'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )
    
    def update(self, request, *args, **kwargs):
        """Disabled update method."""
        return Response(
            {'error': 'Update operation not allowed'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )
    
    def destroy(self, request, *args, **kwargs):
        """Disabled delete method."""
        return Response(
            {'error': 'Delete operation not allowed'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )