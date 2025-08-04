"""Base Celery task class with enhanced functionality."""

import logging
import traceback
from typing import Any, Dict, Optional, Union
from datetime import datetime, timedelta
from celery import Task
from celery.exceptions import Retry, WorkerLostError
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger(__name__)


class BaseTask(Task):
    """
    Base task class with retry logic, logging, and tracing.
    """
    
    # Default retry settings
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 3, 'countdown': 60}
    retry_backoff = True
    retry_backoff_max = 600  # 10 minutes
    retry_jitter = True
    
    # Task settings
    track_started = True
    acks_late = True
    reject_on_worker_lost = True
    
    def __init__(self):
        """Initialize task with logging setup."""
        super().__init__()
        self.task_id = None
        self.start_time = None
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def before_start(self, task_id: str, args: tuple, kwargs: dict):
        """Called before task execution starts."""
        self.task_id = task_id
        self.start_time = timezone.now()
        
        self.logger.info(
            f"Task {self.name} started",
            extra={
                'task_id': task_id,
                'task_name': self.name,
                'args': args,
                'kwargs': kwargs,
                'start_time': self.start_time.isoformat(),
            }
        )
        
        # Set task status in cache
        self._set_task_status('STARTED', {
            'start_time': self.start_time.isoformat(),
            'args': args,
            'kwargs': kwargs,
        })
    
    def on_success(self, retval: Any, task_id: str, args: tuple, kwargs: dict):
        """Called when task succeeds."""
        end_time = timezone.now()
        duration = (end_time - self.start_time).total_seconds() if self.start_time else None
        
        self.logger.info(
            f"Task {self.name} completed successfully",
            extra={
                'task_id': task_id,
                'task_name': self.name,
                'duration': duration,
                'result': str(retval)[:500],  # Truncate large results
                'end_time': end_time.isoformat(),
            }
        )
        
        # Update task status in cache
        self._set_task_status('SUCCESS', {
            'end_time': end_time.isoformat(),
            'duration': duration,
            'result': retval,
        })
    
    def on_failure(self, exc: Exception, task_id: str, args: tuple, kwargs: dict, einfo):
        """Called when task fails."""
        end_time = timezone.now()
        duration = (end_time - self.start_time).total_seconds() if self.start_time else None
        
        self.logger.error(
            f"Task {self.name} failed",
            extra={
                'task_id': task_id,
                'task_name': self.name,
                'duration': duration,
                'error': str(exc),
                'error_type': exc.__class__.__name__,
                'traceback': str(einfo),
                'args': args,
                'kwargs': kwargs,
                'end_time': end_time.isoformat(),
            },
            exc_info=True
        )
        
        # Update task status in cache
        self._set_task_status('FAILURE', {
            'end_time': end_time.isoformat(),
            'duration': duration,
            'error': str(exc),
            'error_type': exc.__class__.__name__,
            'traceback': str(einfo),
        })
    
    def on_retry(self, exc: Exception, task_id: str, args: tuple, kwargs: dict, einfo):
        """Called when task is retried."""
        retry_count = self.request.retries
        
        self.logger.warning(
            f"Task {self.name} retry {retry_count}/{self.max_retries}",
            extra={
                'task_id': task_id,
                'task_name': self.name,
                'retry_count': retry_count,
                'max_retries': self.max_retries,
                'error': str(exc),
                'error_type': exc.__class__.__name__,
                'args': args,
                'kwargs': kwargs,
            }
        )
        
        # Update task status in cache
        self._set_task_status('RETRY', {
            'retry_count': retry_count,
            'max_retries': self.max_retries,
            'error': str(exc),
            'next_retry': self._calculate_next_retry().isoformat(),
        })
    
    def _set_task_status(self, status: str, data: Dict[str, Any]):
        """Set task status in cache."""
        if not self.task_id:
            return
        
        cache_key = f"task_status:{self.task_id}"
        status_data = {
            'task_id': self.task_id,
            'task_name': self.name,
            'status': status,
            'updated_at': timezone.now().isoformat(),
            **data
        }
        
        # Cache for 1 hour
        cache.set(cache_key, status_data, timeout=3600)
    
    def _calculate_next_retry(self) -> datetime:
        """Calculate next retry time."""
        retry_count = self.request.retries
        countdown = self.retry_kwargs.get('countdown', 60)
        
        if self.retry_backoff:
            # Exponential backoff
            countdown = min(countdown * (2 ** retry_count), self.retry_backoff_max)
        
        return timezone.now() + timedelta(seconds=countdown)
    
    def get_task_status(self) -> Optional[Dict[str, Any]]:
        """Get current task status from cache."""
        if not self.task_id:
            return None
        
        cache_key = f"task_status:{self.task_id}"
        return cache.get(cache_key)
    
    def update_progress(self, current: int, total: int, message: str = ""):
        """Update task progress."""
        if not self.task_id:
            return
        
        progress = {
            'current': current,
            'total': total,
            'percentage': round((current / total) * 100, 2) if total > 0 else 0,
            'message': message,
            'updated_at': timezone.now().isoformat(),
        }
        
        # Update task state
        self.update_state(
            state='PROGRESS',
            meta=progress
        )
        
        # Also cache the progress
        cache_key = f"task_progress:{self.task_id}"
        cache.set(cache_key, progress, timeout=3600)
        
        self.logger.info(
            f"Task {self.name} progress: {progress['percentage']}%",
            extra={
                'task_id': self.task_id,
                'task_name': self.name,
                'progress': progress,
            }
        )
    
    def set_result_cache(self, key: str, value: Any, timeout: int = 3600):
        """Cache task result data."""
        cache_key = f"task_result:{self.task_id}:{key}"
        cache.set(cache_key, value, timeout=timeout)
    
    def get_result_cache(self, key: str) -> Any:
        """Get cached task result data."""
        cache_key = f"task_result:{self.task_id}:{key}"
        return cache.get(cache_key)
    
    def log_performance_metrics(self, operation: str, duration: float, **metrics):
        """Log performance metrics."""
        self.logger.info(
            f"Task {self.name} performance metrics",
            extra={
                'task_id': self.task_id,
                'task_name': self.name,
                'operation': operation,
                'duration': duration,
                'metrics': metrics,
            }
        )
    
    def validate_input(self, *args, **kwargs):
        """Validate task input parameters. Override in subclasses."""
        pass
    
    def run(self, *args, **kwargs):
        """
        The task execution method. Override this in subclasses.
        This method includes input validation and error handling.
        """
        try:
            # Validate input
            self.validate_input(*args, **kwargs)
            
            # Execute the actual task logic
            return self.execute(*args, **kwargs)
            
        except Exception as exc:
            self.logger.error(
                f"Task {self.name} execution failed",
                extra={
                    'task_id': self.task_id,
                    'task_name': self.name,
                    'error': str(exc),
                    'args': args,
                    'kwargs': kwargs,
                },
                exc_info=True
            )
            raise
    
    def execute(self, *args, **kwargs):
        """
        Override this method in subclasses to implement task logic.
        """
        raise NotImplementedError("Subclasses must implement the execute method")


class DatabaseTask(BaseTask):
    """Base task for database operations."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 3, 'countdown': 30}
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle database-specific failures."""
        super().on_failure(exc, task_id, args, kwargs, einfo)
        
        # Check for specific database errors
        if 'database' in str(exc).lower() or 'connection' in str(exc).lower():
            self.logger.error(
                f"Database error in task {self.name}",
                extra={
                    'task_id': task_id,
                    'error_type': 'database_error',
                    'error': str(exc),
                }
            )


class ExternalAPITask(BaseTask):
    """Base task for external API calls."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 5, 'countdown': 120}
    retry_backoff = True
    retry_backoff_max = 1200  # 20 minutes
    
    def execute(self, *args, **kwargs):
        """Execute with timeout and rate limiting."""
        # Add request timeout and rate limiting logic
        return super().execute(*args, **kwargs)


class FileProcessingTask(BaseTask):
    """Base task for file processing operations."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 3, 'countdown': 60}
    
    def validate_input(self, file_path: str = None, *args, **kwargs):
        """Validate file path input."""
        if not file_path:
            raise ValueError("file_path is required")
        
        import os
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")


class BatchProcessingTask(BaseTask):
    """Base task for batch processing operations."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 2, 'countdown': 300}
    
    def process_batch(self, items: list, batch_size: int = 100):
        """Process items in batches with progress tracking."""
        total_items = len(items)
        processed_items = 0
        
        for i in range(0, total_items, batch_size):
            batch = items[i:i + batch_size]
            
            try:
                # Process batch
                self.process_batch_items(batch)
                processed_items += len(batch)
                
                # Update progress
                self.update_progress(
                    processed_items,
                    total_items,
                    f"Processed {processed_items}/{total_items} items"
                )
                
            except Exception as e:
                self.logger.error(
                    f"Error processing batch {i//batch_size + 1}",
                    extra={
                        'task_id': self.task_id,
                        'batch_start': i,
                        'batch_size': len(batch),
                        'error': str(e),
                    }
                )
                raise
        
        return {
            'total_processed': processed_items,
            'total_items': total_items,
            'success': True
        }
    
    def process_batch_items(self, batch: list):
        """Override this method to implement batch processing logic."""
        raise NotImplementedError("Subclasses must implement process_batch_items")


class ScheduledTask(BaseTask):
    """Base task for scheduled/periodic operations."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 3, 'countdown': 300}
    
    def __init__(self):
        super().__init__()
        self.last_run_key = f"last_run:{self.name}"
    
    def should_run(self) -> bool:
        """Check if task should run based on schedule."""
        last_run = cache.get(self.last_run_key)
        if not last_run:
            return True
        
        # Override in subclasses to implement custom scheduling logic
        return True
    
    def mark_as_run(self):
        """Mark task as run."""
        cache.set(self.last_run_key, timezone.now().isoformat(), timeout=86400)  # 24 hours
    
    def execute(self, *args, **kwargs):
        """Execute scheduled task."""
        if not self.should_run():
            self.logger.info(
                f"Scheduled task {self.name} skipped - not due to run",
                extra={'task_id': self.task_id}
            )
            return {'skipped': True, 'reason': 'not_due_to_run'}
        
        try:
            result = super().execute(*args, **kwargs)
            self.mark_as_run()
            return result
        except Exception:
            # Don't mark as run if task failed
            raise


# Task utilities
def get_task_status(task_id: str) -> Optional[Dict[str, Any]]:
    """Get task status from cache."""
    cache_key = f"task_status:{task_id}"
    return cache.get(cache_key)


def get_task_progress(task_id: str) -> Optional[Dict[str, Any]]:
    """Get task progress from cache."""
    cache_key = f"task_progress:{task_id}"
    return cache.get(cache_key)


def cancel_task(task_id: str, terminate: bool = False):
    """Cancel a running task."""
    from celery import current_app
    
    if terminate:
        current_app.control.terminate(task_id)
    else:
        current_app.control.revoke(task_id, terminate=False)
    
    # Update status in cache
    cache_key = f"task_status:{task_id}"
    status_data = cache.get(cache_key) or {}
    status_data.update({
        'status': 'CANCELLED',
        'cancelled_at': timezone.now().isoformat(),
    })
    cache.set(cache_key, status_data, timeout=3600)


# Decorators for common task patterns
def track_task_metrics(func):
    """Decorator to track task execution metrics."""
    def wrapper(self, *args, **kwargs):
        start_time = timezone.now()
        try:
            result = func(self, *args, **kwargs)
            duration = (timezone.now() - start_time).total_seconds()
            self.log_performance_metrics(
                operation=func.__name__,
                duration=duration,
                status='success'
            )
            return result
        except Exception as e:
            duration = (timezone.now() - start_time).total_seconds()
            self.log_performance_metrics(
                operation=func.__name__,
                duration=duration,
                status='error',
                error=str(e)
            )
            raise
    return wrapper


def require_lock(lock_key: str, timeout: int = 300):
    """Decorator to ensure only one instance of a task runs at a time."""
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            lock_cache_key = f"task_lock:{lock_key}"
            
            # Try to acquire lock
            if cache.get(lock_cache_key):
                raise Exception(f"Task {self.name} is already running")
            
            cache.set(lock_cache_key, self.task_id, timeout=timeout)
            
            try:
                result = func(self, *args, **kwargs)
                return result
            finally:
                # Release lock
                cache.delete(lock_cache_key)
        
        return wrapper
    return decorator