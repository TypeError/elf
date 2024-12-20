"""Custom exceptions for API clients.

Provides granular error handling for interacting with external services.

Classes:
    ApiClientError
    ApiClientHTTPError
    ApiClientTimeoutError
    ApiClientNetworkError
    ApiClientDataError
"""

from __future__ import annotations


class ApiClientError(Exception):
    """Base exception for general API client errors.

    Attributes:
        message: A descriptive error message.

    """

    def __init__(self, message: str, *args: object) -> None:
        """Initialize the ApiClientError with a message.

        Args:
            message: A descriptive error message.
            *args: Additional arguments to pass to the base Exception class.

        """
        super().__init__(message, *args)
        self.message = message


class ApiClientHTTPError(ApiClientError):
    """Exception raised for HTTP errors (4xx, 5xx).

    Attributes:
        status_code: The HTTP status code.
        response_text: The response text from the server.

    """

    def __init__(self, status_code: int, response_text: str) -> None:
        """Initialize the ApiClientHTTPError with status code and response text.

        Args:
            status_code: The HTTP status code.
            response_text: The response text from the server.

        """
        message = f"HTTP error {status_code}: {response_text}"
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class ApiClientTimeoutError(ApiClientError):
    """Exception raised for request timeouts."""


class ApiClientNetworkError(ApiClientError):
    """Exception raised for network-related errors."""


class ApiClientDataError(ApiClientError):
    """Exception raised for data-related issues (e.g., parsing or validation)."""
