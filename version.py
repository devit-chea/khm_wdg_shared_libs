"""Version information for django-shared-libs."""

__version__ = "1.0.0"
__version_info__ = tuple(int(num) for num in __version__.split('.'))

# Release information
RELEASE_LEVEL = "stable"  # alpha, beta, rc, stable
RELEASE_SERIAL = 0

def get_version():
    """Return the version string."""
    return __version__

def get_version_info():
    """Return version info as a tuple."""
    return __version_info__

def get_full_version():
    """Return full version info including release level."""
    version = __version__
    if RELEASE_LEVEL != "stable":
        version += f"-{RELEASE_LEVEL}"
        if RELEASE_SERIAL:
            version += f".{RELEASE_SERIAL}"
    return version