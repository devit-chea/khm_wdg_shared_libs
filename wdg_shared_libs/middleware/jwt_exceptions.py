class JWTError(Exception):
    """Base JWT exception"""
    pass


class JWTConfigurationError(JWTError):
    """JWT configuration error"""
    pass


class JWTValidationError(JWTError):
    """JWT validation error"""
    pass


class JWTKeyError(JWTError):
    """JWT key loading error"""
    pass