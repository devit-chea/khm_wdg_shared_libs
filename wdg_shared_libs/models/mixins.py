"""Model mixins for common functionality."""

import uuid
from typing import Optional
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.text import slugify
from django.core.exceptions import ValidationError
from ..utils.common import generate_uuid4, slugify as custom_slugify


class TimestampMixin(models.Model):
    """Mixin for timestamp fields."""
    
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the record was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp when the record was last updated"
    )
    
    class Meta:
        abstract = True


class UUIDMixin(models.Model):
    """Mixin for UUID primary key."""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier"
    )
    
    class Meta:
        abstract = True


class SlugMixin(models.Model):
    """Mixin for slug fields."""
    
    slug = models.SlugField(
        max_length=255,
        unique=True,
        help_text="URL-friendly version of the name"
    )
    
    class Meta:
        abstract = True
    
    def save(self, *args, **kwargs):
        """Auto-generate slug if not provided."""
        if not self.slug and hasattr(self, 'name'):
            self.slug = self._generate_unique_slug(self.name)
        super().save(*args, **kwargs)
    
    def _generate_unique_slug(self, text: str) -> str:
        """Generate a unique slug for the given text."""
        base_slug = custom_slugify(text)
        slug = base_slug
        counter = 1
        
        while self.__class__.objects.filter(slug=slug).exclude(pk=self.pk).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        return slug


class SoftDeleteMixin(models.Model):
    """Mixin for soft delete functionality."""
    
    is_deleted = models.BooleanField(
        default=False,
        help_text="Whether the record is soft deleted"
    )
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the record was deleted"
    )
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_deleted",
        help_text="User who deleted the record"
    )
    
    class Meta:
        abstract = True
    
    def delete(self, user=None, using=None, keep_parents=False):
        """Soft delete the instance."""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        if user:
            self.deleted_by = user
        self.save(using=using, update_fields=['is_deleted', 'deleted_at', 'deleted_by'])
    
    def hard_delete(self, using=None, keep_parents=False):
        """Permanently delete the instance."""
        super().delete(using=using, keep_parents=keep_parents)
    
    def restore(self):
        """Restore a soft-deleted instance."""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by'])


class AuditMixin(models.Model):
    """Mixin for audit fields."""
    
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_created",
        help_text="User who created the record"
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_updated",
        help_text="User who last updated the record"
    )
    
    class Meta:
        abstract = True


class VersionMixin(models.Model):
    """Mixin for version control."""
    
    version = models.PositiveIntegerField(
        default=1,
        help_text="Version number for optimistic locking"
    )
    
    class Meta:
        abstract = True
    
    def save(self, *args, **kwargs):
        """Increment version on save."""
        if self.pk:
            self.version += 1
        super().save(*args, **kwargs)


class StatusMixin(models.Model):
    """Mixin for status fields."""
    
    class StatusChoices(models.TextChoices):
        ACTIVE = 'active', 'Active'
        INACTIVE = 'inactive', 'Inactive'
        PENDING = 'pending', 'Pending'
        ARCHIVED = 'archived', 'Archived'
    
    status = models.CharField(
        max_length=20,
        choices=StatusChoices.choices,
        default=StatusChoices.ACTIVE,
        help_text="Current status of the record"
    )
    
    class Meta:
        abstract = True


class OrderingMixin(models.Model):
    """Mixin for ordering/position fields."""
    
    order = models.PositiveIntegerField(
        default=0,
        help_text="Order/position of the record"
    )
    
    class Meta:
        abstract = True
        ordering = ['order']


class MetadataMixin(models.Model):
    """Mixin for JSON metadata fields."""
    
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional metadata as JSON"
    )
    
    class Meta:
        abstract = True
    
    def get_metadata(self, key: str, default=None):
        """Get metadata value by key."""
        return self.metadata.get(key, default)
    
    def set_metadata(self, key: str, value):
        """Set metadata value by key."""
        self.metadata[key] = value
        self.save(update_fields=['metadata'])
    
    def update_metadata(self, data: dict):
        """Update multiple metadata values."""
        self.metadata.update(data)
        self.save(update_fields=['metadata'])


class PublishMixin(models.Model):
    """Mixin for publishable content."""
    
    is_published = models.BooleanField(
        default=False,
        help_text="Whether the content is published"
    )
    published_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the content was published"
    )
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_published",
        help_text="User who published the content"
    )
    
    class Meta:
        abstract = True
    
    def publish(self, user=None):
        """Publish the content."""
        self.is_published = True
        self.published_at = timezone.now()
        if user:
            self.published_by = user
        self.save(update_fields=['is_published', 'published_at', 'published_by'])
    
    def unpublish(self):
        """Unpublish the content."""
        self.is_published = False
        self.published_at = None
        self.published_by = None
        self.save(update_fields=['is_published', 'published_at', 'published_by'])


class ActivationMixin(models.Model):
    """Mixin for activatable content."""
    
    is_active = models.BooleanField(
        default=True,
        help_text="Whether the record is active"
    )
    activated_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the record was activated"
    )
    deactivated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the record was deactivated"
    )
    
    class Meta:
        abstract = True
    
    def activate(self):
        """Activate the record."""
        self.is_active = True
        self.activated_at = timezone.now()
        self.deactivated_at = None
        self.save(update_fields=['is_active', 'activated_at', 'deactivated_at'])
    
    def deactivate(self):
        """Deactivate the record."""
        self.is_active = False
        self.deactivated_at = timezone.now()
        self.save(update_fields=['is_active', 'deactivated_at'])


class ExpirationMixin(models.Model):
    """Mixin for expirable content."""
    
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the record expires"
    )
    
    class Meta:
        abstract = True
    
    @property
    def is_expired(self) -> bool:
        """Check if the record is expired."""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def set_expiration(self, days: int = None, hours: int = None, minutes: int = None):
        """Set expiration time from now."""
        if not any([days, hours, minutes]):
            raise ValueError("At least one time parameter must be provided")
        
        from datetime import timedelta
        delta = timedelta(days=days or 0, hours=hours or 0, minutes=minutes or 0)
        self.expires_at = timezone.now() + delta
        self.save(update_fields=['expires_at'])


class CounterMixin(models.Model):
    """Mixin for counter fields."""
    
    view_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of views"
    )
    
    class Meta:
        abstract = True
    
    def increment_view_count(self):
        """Increment view count."""
        self.__class__.objects.filter(pk=self.pk).update(
            view_count=models.F('view_count') + 1
        )
        self.refresh_from_db(fields=['view_count'])


class TreeMixin(models.Model):
    """Mixin for tree/hierarchical structures."""
    
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children',
        help_text="Parent record"
    )
    level = models.PositiveIntegerField(
        default=0,
        help_text="Level in the tree hierarchy"
    )
    
    class Meta:
        abstract = True
    
    def save(self, *args, **kwargs):
        """Auto-calculate level based on parent."""
        if self.parent:
            self.level = self.parent.level + 1
        else:
            self.level = 0
        super().save(*args, **kwargs)
    
    def get_ancestors(self):
        """Get all ancestors of this node."""
        ancestors = []
        current = self.parent
        while current:
            ancestors.append(current)
            current = current.parent
        return ancestors
    
    def get_descendants(self):
        """Get all descendants of this node."""
        descendants = []
        for child in self.children.all():
            descendants.append(child)
            descendants.extend(child.get_descendants())
        return descendants
    
    def is_ancestor_of(self, node):
        """Check if this node is an ancestor of the given node."""
        return self in node.get_ancestors()
    
    def is_descendant_of(self, node):
        """Check if this node is a descendant of the given node."""
        return node in self.get_ancestors()


class BaseModel(UUIDMixin, TimestampMixin, AuditMixin, SoftDeleteMixin):
    """Base model with commonly used mixins."""
    
    class Meta:
        abstract = True


class NamedModel(BaseModel):
    """Base model for named entities."""
    
    name = models.CharField(
        max_length=255,
        help_text="Name of the entity"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of the entity"
    )
    
    class Meta:
        abstract = True
    
    def __str__(self):
        return self.name


class SluggedModel(NamedModel, SlugMixin):
    """Base model for named entities with slugs."""
    
    class Meta:
        abstract = True


class PublishableModel(NamedModel, PublishMixin, StatusMixin):
    """Base model for publishable content."""
    
    class Meta:
        abstract = True


class OrderedModel(BaseModel, OrderingMixin):
    """Base model for ordered entities."""
    
    class Meta:
        abstract = True


class CacheInvalidationMixin(models.Model):
    """Mixin for cache invalidation."""
    
    class Meta:
        abstract = True
    
    def get_cache_keys(self):
        """Return list of cache keys to invalidate."""
        return []
    
    def invalidate_cache(self):
        """Invalidate related cache entries."""
        from django.core.cache import cache
        cache_keys = self.get_cache_keys()
        if cache_keys:
            cache.delete_many(cache_keys)
    
    def save(self, *args, **kwargs):
        """Save and invalidate cache."""
        super().save(*args, **kwargs)
        self.invalidate_cache()
    
    def delete(self, *args, **kwargs):
        """Delete and invalidate cache."""
        self.invalidate_cache()
        super().delete(*args, **kwargs)


class ValidatedModel(models.Model):
    """Mixin for model validation."""
    
    class Meta:
        abstract = True
    
    def clean(self):
        """Override to add custom validation."""
        super().clean()
    
    def save(self, *args, **kwargs):
        """Save with validation."""
        if not kwargs.pop('skip_validation', False):
            self.full_clean()
        super().save(*args, **kwargs)


class TrackableModel(BaseModel, VersionMixin, MetadataMixin):
    """Model with comprehensive tracking capabilities."""
    
    class Meta:
        abstract = True