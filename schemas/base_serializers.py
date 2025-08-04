"""Base serializer classes for consistent API responses."""

from typing import Any, Dict, List, Optional, Union
from rest_framework import serializers
from rest_framework.fields import empty
from django.core.paginator import Page
from django.utils import timezone
from ..utils.common import generate_uuid4


class TimestampMixin(serializers.Serializer):
    """Mixin for timestamp fields."""
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class BaseResponseSerializer(serializers.Serializer):
    """Base response serializer with common fields."""
    
    success = serializers.BooleanField(default=True, read_only=True)
    message = serializers.CharField(default="Operation completed successfully", read_only=True)
    timestamp = serializers.DateTimeField(default=timezone.now, read_only=True)
    request_id = serializers.CharField(default=generate_uuid4, read_only=True)


class ErrorResponseSerializer(BaseResponseSerializer):
    """Error response serializer."""
    
    success = serializers.BooleanField(default=False, read_only=True)
    error = serializers.BooleanField(default=True, read_only=True)
    code = serializers.CharField(read_only=True)
    message = serializers.CharField(read_only=True)
    category = serializers.CharField(read_only=True)
    details = serializers.JSONField(required=False, read_only=True)


class PaginationSerializer(serializers.Serializer):
    """Pagination metadata serializer."""
    
    count = serializers.IntegerField(help_text="Total number of items")
    page = serializers.IntegerField(help_text="Current page number")
    pages = serializers.IntegerField(help_text="Total number of pages")
    page_size = serializers.IntegerField(help_text="Number of items per page")
    has_next = serializers.BooleanField(help_text="Whether there is a next page")
    has_previous = serializers.BooleanField(help_text="Whether there is a previous page")
    next_page = serializers.IntegerField(allow_null=True, help_text="Next page number")
    previous_page = serializers.IntegerField(allow_null=True, help_text="Previous page number")


class PaginatedResponseSerializer(BaseResponseSerializer):
    """Paginated response serializer."""
    
    data = serializers.ListField(read_only=True)
    pagination = PaginationSerializer(read_only=True)
    
    def __init__(self, *args, **kwargs):
        """Initialize with data serializer."""
        self.data_serializer = kwargs.pop('data_serializer', None)
        super().__init__(*args, **kwargs)
        
        if self.data_serializer:
            self.fields['data'] = serializers.ListField(
                child=self.data_serializer(),
                read_only=True
            )


class SingleItemResponseSerializer(BaseResponseSerializer):
    """Single item response serializer."""
    
    data = serializers.JSONField(read_only=True)
    
    def __init__(self, *args, **kwargs):
        """Initialize with data serializer."""
        self.data_serializer = kwargs.pop('data_serializer', None)
        super().__init__(*args, **kwargs)
        
        if self.data_serializer:
            self.fields['data'] = self.data_serializer(read_only=True)


class BulkOperationResponseSerializer(BaseResponseSerializer):
    """Bulk operation response serializer."""
    
    total = serializers.IntegerField(help_text="Total number of items processed")
    successful = serializers.IntegerField(help_text="Number of successful operations")
    failed = serializers.IntegerField(help_text="Number of failed operations")
    errors = serializers.ListField(
        child=serializers.JSONField(),
        required=False,
        help_text="List of errors for failed operations"
    )


class BaseModelSerializer(serializers.ModelSerializer):
    """Base model serializer with common functionality."""
    
    class Meta:
        abstract = True
    
    def __init__(self, *args, **kwargs):
        """Initialize with dynamic field selection."""
        fields = kwargs.pop('fields', None)
        exclude = kwargs.pop('exclude', None)
        
        super().__init__(*args, **kwargs)
        
        if fields is not None:
            # Drop fields not in the `fields` argument
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)
        
        if exclude is not None:
            # Drop fields in the `exclude` argument
            for field_name in exclude:
                self.fields.pop(field_name, None)
    
    def to_representation(self, instance):
        """Add custom representation logic."""
        data = super().to_representation(instance)
        
        # Remove null values if configured
        if getattr(self.Meta, 'exclude_null_values', False):
            data = {k: v for k, v in data.items() if v is not None}
        
        return data
    
    def validate(self, attrs):
        """Add custom validation logic."""
        # Call model's clean method if it exists
        if hasattr(self.Meta.model, 'clean'):
            instance = self.Meta.model(**attrs)
            instance.clean()
        
        return super().validate(attrs)


class AuditMixin(serializers.Serializer):
    """Mixin for audit fields."""
    
    created_by = serializers.StringRelatedField(read_only=True)
    updated_by = serializers.StringRelatedField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class SoftDeleteMixin(serializers.Serializer):
    """Mixin for soft delete fields."""
    
    is_deleted = serializers.BooleanField(read_only=True)
    deleted_at = serializers.DateTimeField(read_only=True, allow_null=True)
    deleted_by = serializers.StringRelatedField(read_only=True, allow_null=True)


class VersionMixin(serializers.Serializer):
    """Mixin for version control."""
    
    version = serializers.IntegerField(read_only=True)


class SlugMixin(serializers.Serializer):
    """Mixin for slug fields."""
    
    slug = serializers.SlugField(read_only=True)


class NestedCreateMixin:
    """Mixin for handling nested object creation."""
    
    def create_nested_objects(self, validated_data, nested_fields):
        """Create nested objects and return their instances."""
        nested_objects = {}
        
        for field_name in nested_fields:
            if field_name in validated_data:
                nested_data = validated_data.pop(field_name)
                if nested_data:
                    nested_serializer_class = self.fields[field_name].__class__
                    nested_serializer = nested_serializer_class(data=nested_data)
                    nested_serializer.is_valid(raise_exception=True)
                    nested_objects[field_name] = nested_serializer.save()
        
        return nested_objects


class DynamicFieldsMixin:
    """Mixin for dynamic field inclusion/exclusion."""
    
    def __init__(self, *args, **kwargs):
        """Initialize with dynamic fields support."""
        # Don't pass the 'fields' or 'exclude' arg up to the superclass
        fields = kwargs.pop('fields', None)
        exclude = kwargs.pop('exclude', None)
        
        # Get fields from request context
        request = self.context.get('request')
        if request:
            query_params = request.query_params
            if 'fields' in query_params:
                fields = query_params['fields'].split(',')
            if 'exclude' in query_params:
                exclude = query_params['exclude'].split(',')
        
        super().__init__(*args, **kwargs)
        
        if fields is not None:
            # Drop any fields that are not specified in the `fields` argument
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)
        
        if exclude is not None:
            # Drop fields specified in the `exclude` argument
            for field_name in exclude:
                self.fields.pop(field_name, None)


class BaseCreateSerializer(BaseModelSerializer):
    """Base serializer for create operations."""
    
    class Meta:
        abstract = True
        exclude_null_values = True
    
    def create(self, validated_data):
        """Create instance with current user."""
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            if hasattr(self.Meta.model, 'created_by'):
                validated_data['created_by'] = request.user
        
        return super().create(validated_data)


class BaseUpdateSerializer(BaseModelSerializer):
    """Base serializer for update operations."""
    
    class Meta:
        abstract = True
        exclude_null_values = True
    
    def update(self, instance, validated_data):
        """Update instance with current user."""
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            if hasattr(instance, 'updated_by'):
                validated_data['updated_by'] = request.user
        
        return super().update(instance, validated_data)


class ReadOnlySerializer(BaseModelSerializer):
    """Base read-only serializer."""
    
    class Meta:
        abstract = True
    
    def create(self, validated_data):
        """Prevent creation."""
        raise NotImplementedError("This serializer is read-only")
    
    def update(self, instance, validated_data):
        """Prevent updates."""
        raise NotImplementedError("This serializer is read-only")


class BulkCreateSerializer(serializers.ListSerializer):
    """Serializer for bulk create operations."""
    
    def create(self, validated_data):
        """Create multiple instances."""
        return [self.child.create(attrs) for attrs in validated_data]
    
    def update(self, instance, validated_data):
        """Bulk update is not supported by default."""
        raise NotImplementedError("Bulk update not supported")


class BulkUpdateSerializer(serializers.ListSerializer):
    """Serializer for bulk update operations."""
    
    def update(self, instance, validated_data):
        """Update multiple instances."""
        # Maps for id->instance and id->data item
        instance_mapping = {item.id: item for item in instance}
        data_mapping = {item['id']: item for item in validated_data}
        
        # Perform updates
        updated_instances = []
        for item_id, data in data_mapping.items():
            instance = instance_mapping.get(item_id)
            if instance:
                updated_instance = self.child.update(instance, data)
                updated_instances.append(updated_instance)
        
        return updated_instances


def create_response_serializer(data_serializer_class, paginated=False):
    """
    Factory function to create response serializers.
    
    Args:
        data_serializer_class: The serializer class for the data field
        paginated: Whether to create a paginated response serializer
    
    Returns:
        Response serializer class
    """
    if paginated:
        class ResponseSerializer(PaginatedResponseSerializer):
            data = serializers.ListField(child=data_serializer_class(), read_only=True)
        
        return ResponseSerializer
    else:
        class ResponseSerializer(SingleItemResponseSerializer):
            data = data_serializer_class(read_only=True)
        
        return ResponseSerializer