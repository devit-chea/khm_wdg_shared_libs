"""DateTime utility functions."""

import pytz
from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from django.utils import timezone as django_timezone
from django.conf import settings


def now() -> datetime:
    """Get current datetime in UTC."""
    return django_timezone.now()


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def local_now() -> datetime:
    """Get current datetime in local timezone."""
    return django_timezone.localtime()


def to_utc(dt: datetime) -> datetime:
    """
    Convert datetime to UTC.
    
    Args:
        dt: Datetime to convert
    
    Returns:
        UTC datetime
    """
    if dt.tzinfo is None:
        # Assume naive datetime is in local timezone
        dt = django_timezone.make_aware(dt)
    return dt.astimezone(timezone.utc)


def to_local(dt: datetime, tz: Optional[str] = None) -> datetime:
    """
    Convert datetime to local timezone.
    
    Args:
        dt: Datetime to convert
        tz: Target timezone name (defaults to Django TIME_ZONE)
    
    Returns:
        Local datetime
    """
    if tz:
        target_tz = pytz.timezone(tz)
    else:
        target_tz = django_timezone.get_current_timezone()
    
    if dt.tzinfo is None:
        dt = django_timezone.make_aware(dt, timezone=timezone.utc)
    
    return dt.astimezone(target_tz)


def parse_datetime(dt_str: str, fmt: Optional[str] = None) -> Optional[datetime]:
    """
    Parse datetime string.
    
    Args:
        dt_str: Datetime string
        fmt: Format string (if None, tries common formats)
    
    Returns:
        Parsed datetime or None
    """
    if fmt:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            return None
    
    # Try common formats
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%d',
        '%d/%m/%Y',
        '%m/%d/%Y',
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    
    return None


def format_datetime(dt: datetime, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format datetime to string.
    
    Args:
        dt: Datetime to format
        fmt: Format string
    
    Returns:
        Formatted datetime string
    """
    return dt.strftime(fmt)


def get_date_range(start_date: datetime, end_date: datetime) -> list:
    """
    Get list of dates between start and end date.
    
    Args:
        start_date: Start date
        end_date: End date
    
    Returns:
        List of dates
    """
    dates = []
    current_date = start_date.date()
    end_date = end_date.date()
    
    while current_date <= end_date:
        dates.append(current_date)
        current_date += timedelta(days=1)
    
    return dates


def get_weekday_name(date: datetime, locale: str = 'en') -> str:
    """
    Get weekday name for given date.
    
    Args:
        date: Date to get weekday for
        locale: Locale for weekday name
    
    Returns:
        Weekday name
    """
    weekdays = {
        'en': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
        'es': ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo'],
        'fr': ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche'],
    }
    
    weekday_list = weekdays.get(locale, weekdays['en'])
    return weekday_list[date.weekday()]


def get_month_name(date: datetime, locale: str = 'en') -> str:
    """
    Get month name for given date.
    
    Args:
        date: Date to get month for
        locale: Locale for month name
    
    Returns:
        Month name
    """
    months = {
        'en': ['January', 'February', 'March', 'April', 'May', 'June',
               'July', 'August', 'September', 'October', 'November', 'December'],
        'es': ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
               'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'],
        'fr': ['Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
               'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'],
    }
    
    month_list = months.get(locale, months['en'])
    return month_list[date.month - 1]


def time_ago(dt: datetime) -> str:
    """
    Get human-readable time ago string.
    
    Args:
        dt: Datetime to compare
    
    Returns:
        Time ago string
    """
    now_dt = now()
    if dt.tzinfo is None:
        dt = django_timezone.make_aware(dt)
    
    diff = now_dt - dt
    
    if diff.days > 365:
        years = diff.days // 365
        return f"{years} year{'s' if years > 1 else ''} ago"
    elif diff.days > 30:
        months = diff.days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"


def is_business_day(date: datetime) -> bool:
    """
    Check if date is a business day (Monday-Friday).
    
    Args:
        date: Date to check
    
    Returns:
        True if business day, False otherwise
    """
    return date.weekday() < 5


def get_business_days_count(start_date: datetime, end_date: datetime) -> int:
    """
    Count business days between two dates.
    
    Args:
        start_date: Start date
        end_date: End date
    
    Returns:
        Number of business days
    """
    count = 0
    current_date = start_date.date()
    end_date = end_date.date()
    
    while current_date <= end_date:
        if current_date.weekday() < 5:  # Monday = 0, Friday = 4
            count += 1
        current_date += timedelta(days=1)
    
    return count


def get_timezone_offset(tz_name: str) -> str:
    """
    Get timezone offset string.
    
    Args:
        tz_name: Timezone name
    
    Returns:
        Offset string (e.g., '+05:30')
    """
    try:
        tz = pytz.timezone(tz_name)
        offset = tz.utcoffset(datetime.now())
        total_seconds = int(offset.total_seconds())
        hours, remainder = divmod(abs(total_seconds), 3600)
        minutes = remainder // 60
        sign = '+' if total_seconds >= 0 else '-'
        return f"{sign}{hours:02d}:{minutes:02d}"
    except Exception:
        return '+00:00'


def start_of_day(dt: datetime) -> datetime:
    """Get start of day for given datetime."""
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def end_of_day(dt: datetime) -> datetime:
    """Get end of day for given datetime."""
    return dt.replace(hour=23, minute=59, second=59, microsecond=999999)


def start_of_week(dt: datetime) -> datetime:
    """Get start of week (Monday) for given datetime."""
    days_since_monday = dt.weekday()
    monday = dt - timedelta(days=days_since_monday)
    return start_of_day(monday)


def end_of_week(dt: datetime) -> datetime:
    """Get end of week (Sunday) for given datetime."""
    days_until_sunday = 6 - dt.weekday()
    sunday = dt + timedelta(days=days_until_sunday)
    return end_of_day(sunday)


def start_of_month(dt: datetime) -> datetime:
    """Get start of month for given datetime."""
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def end_of_month(dt: datetime) -> datetime:
    """Get end of month for given datetime."""
    if dt.month == 12:
        next_month = dt.replace(year=dt.year + 1, month=1, day=1)
    else:
        next_month = dt.replace(month=dt.month + 1, day=1)
    
    last_day = next_month - timedelta(days=1)
    return end_of_day(last_day)