class InteractiveAnalysisError(Exception):
    """Base error for runtime failures."""


class InvalidStateError(InteractiveAnalysisError):
    """Raised when an operation is invalid for the current session state."""


class UnsupportedOperationError(InteractiveAnalysisError):
    """Raised when a backend cannot support a requested operation."""


class EventValidationError(InteractiveAnalysisError):
    """Raised when an instrumentation event is malformed."""


class SessionTimeoutError(InteractiveAnalysisError):
    """Raised when a blocking runtime operation times out."""
