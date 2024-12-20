"""Core components of the `elf` package.

This module includes foundational utilities such as:
    - `BaseApiClient`: An abstract base class for building API clients.
    - Custom exceptions for error handling in API interactions.

Public API:
    - `BaseApiClient`
    - `ApiClientError`
    - `ApiClientHTTPError`
    - `ApiClientTimeoutError`
    - `ApiClientNetworkError`
    - `ApiClientDataError`
"""

from .base_api_client import BaseApiClient
from .exceptions import (
    ApiClientDataError,
    ApiClientError,
    ApiClientHTTPError,
    ApiClientNetworkError,
    ApiClientTimeoutError,
)

__all__ = [
    "BaseApiClient",
    "ApiClientError",
    "ApiClientHTTPError",
    "ApiClientTimeoutError",
    "ApiClientNetworkError",
    "ApiClientDataError",
]
