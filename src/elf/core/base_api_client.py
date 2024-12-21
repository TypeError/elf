"""Base API client providing shared functionalities for all API clients.

This module defines the `BaseApiClient` abstract base class, which encapsulates
common functionalities such as:

- HTTP request handling with retries and exponential backoff
- Consistent timeout and error handling logic
- Structured logging for better observability
- Abstract response parsing, to be implemented by subclasses

Subclasses should override `_parse_response` to handle domain-specific parsing of
the HTTP responses into Pydantic models.

Example:
    >>> class MyApiClient(BaseApiClient):
    ...     async def _parse_response(self, response: httpx.Response) -> MyModel:
    ...         return await self._handle_response(response, MyModel)

    >>> async with MyApiClient(base_url="https://api.example.com") as client:
    ...     data = await client._request("GET", "/data")
    ...     parsed = await client._parse_response(data)

"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any, Literal, Self, TypeVar

import httpx
from httpx import AsyncClient, HTTPStatusError, RequestError, TimeoutException
from pydantic import BaseModel, ValidationError

from elf.core.exceptions import (
    ApiClientError,
    ApiClientHTTPError,
    ApiClientNetworkError,
    ApiClientTimeoutError,
)

R = TypeVar("R", bound=BaseModel)

# Commonly retryable status codes indicating transient server errors
RETRYABLE_STATUS_CODES = {500, 502, 503, 504}


class BaseApiClient(ABC):
    """Abstract base class for API clients providing a common framework.

    This class streamlines the implementation of API clients by handling:
    - HTTP requests (async) with retries and exponential backoff
    - Consistent timeout, error handling, and logging
    - Async context management for the underlying HTTP client

    Subclasses must implement:
        - `_parse_response(response: httpx.Response) -> BaseModel`:
          Method to parse API responses into domain-specific models.

    Attributes:
        base_url (str): The base URL for the API endpoint (no trailing slash).
        timeout (float): The request timeout in seconds.
        retries (int): Maximum number of retry attempts for failed requests.
        backoff_factor (float): Factor used to calculate exponential backoff.
        client (AsyncClient): The underlying `httpx.AsyncClient` instance.
        logger (logging.Logger): Logger instance for debugging and error reporting.

    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        retries: int = 3,
        backoff_factor: float = 0.5,
        client: AsyncClient | None = None,
    ) -> None:
        """Initialize the BaseApiClient.

        Args:
            base_url: The base URL for the API (no trailing slash).
            timeout: Timeout in seconds for each HTTP request.
            headers: Optional default headers applied to each request.
            retries: Number of retry attempts if a request fails.
            backoff_factor: Multiplier for exponential backoff timing.
            client: Optionally provide a custom httpx.AsyncClient instance.

        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.backoff_factor = backoff_factor

        # Obtain (but do not forcibly configure) a logger.
        # Users are expected to configure logging themselves if they wish.
        self.logger = logging.getLogger(self.__class__.__name__)

        self.client = client or AsyncClient(
            base_url=self.base_url,
            headers=headers or {},
            timeout=httpx.Timeout(self.timeout),
        )

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources.

        This should be called when the client is no longer needed.
        """
        await self.client.aclose()

    async def __aenter__(self) -> Self:
        """Enter the async context manager.

        Returns:
            Self: The instance of the client, ready for use.

        """
        await self.client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the async context manager and close the client."""
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    @abstractmethod
    async def _parse_response(self, response: httpx.Response) -> BaseModel:
        """Parse the HTTP response into a Pydantic model instance.

        Subclasses must implement this method to convert the raw HTTP response
        into a strongly typed Pydantic model.

        Args:
            response: The `httpx.Response` object to parse.

        Returns:
            A Pydantic model instance representing the parsed response data.

        Raises:
            ApiClientError: If parsing or validation fails.

        """
        pass

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"],
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        response_format: Literal["json", "csv"] = "json",
    ) -> httpx.Response:
        """Perform an HTTP request with retries, backoff, and error handling.

        This method handles:
        - Sending the request using the specified HTTP method and endpoint.
        - Adding query parameters and headers.
        - Automatically retrying failed requests based on the configured retry count.
        - Applying exponential backoff between retry attempts.
        - Logging and raising appropriate exceptions on errors.

        Args:
            method: The HTTP method, e.g., "GET", "POST", "PATCH".
            endpoint: The API endpoint (relative to `base_url`).
            params: Optional query parameters.
            headers: Optional additional headers.
            response_format: Expected response format ("json" or "csv").

        Returns:
            An `httpx.Response` object from the successful request.

        Raises:
            ApiClientHTTPError: If the server returns an unsuccessful status code after all retries.
            ApiClientTimeoutError: If the request times out after all retries.
            ApiClientNetworkError: If a network-related error occurs after all retries.
            ApiClientError: For other unexpected errors.

        """
        url = endpoint.lstrip("/")
        request_headers = self._prepare_headers(headers, response_format)

        for attempt in range(1, self.retries + 1):
            try:
                response = await self._make_request(method, url, params, request_headers, attempt)
                response.raise_for_status()
                return response

            except HTTPStatusError as e:
                # Only retry on typical transient errors (5xx)
                if e.response.status_code not in RETRYABLE_STATUS_CODES:
                    self._handle_http_status_error(e, method, url, attempt)
                    raise ApiClientHTTPError(e.response.status_code, e.response.text) from e

                self._handle_http_status_error(e, method, url, attempt)
                if attempt == self.retries:
                    # Final attempt failed
                    raise ApiClientHTTPError(e.response.status_code, e.response.text) from e

            except TimeoutException as e:
                self._handle_timeout_error(e, method, url, attempt)
                if attempt == self.retries:
                    raise ApiClientTimeoutError("Request timed out") from e

            except RequestError as e:
                self._handle_request_error(e, method, url, attempt)
                if attempt == self.retries:
                    raise ApiClientNetworkError("Network error occurred") from e

            except ValueError as e:
                # Typically indicates JSON decoding or data conversion issue
                self._handle_value_error(e, method, url)
                raise ApiClientError(f"Value error during request: {str(e)}") from e

            # Exponential backoff before the next attempt
            sleep_time = self.backoff_factor * (2 ** (attempt - 1))
            self.logger.debug(f"Attempt {attempt} failed; retrying in {sleep_time:.2f} seconds...")
            await asyncio.sleep(sleep_time)

        # If all attempts somehow fall through without returning or raising,
        # raise a generic error (should rarely happen in practice).
        raise ApiClientError("Failed to obtain a valid response after all retries")

    def _prepare_headers(
        self, headers: dict[str, str] | None, response_format: Literal["json", "csv"]
    ) -> dict[str, str]:
        """Prepare request headers according to the desired response format.

        Args:
            headers: Additional headers provided by the caller.
            response_format: Expected response format ("json" or "csv").

        Returns:
            A dictionary of headers to be used for the request.

        """
        accept_header = "text/csv" if response_format == "csv" else "application/json"
        request_headers = {"Accept": accept_header}
        if headers:
            request_headers.update(headers)
        return request_headers

    async def _make_request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"],
        url: str,
        params: dict[str, Any] | None,
        headers: dict[str, str],
        attempt: int,
    ) -> httpx.Response:
        """Execute the HTTP request with the given parameters.

        Args:
            method: HTTP method to use.
            url: The relative endpoint URL (relative to `base_url`).
            params: Query parameters.
            headers: Prepared headers for the request.
            attempt: The current attempt number.

        Returns:
            An `httpx.Response` object.

        Raises:
            HTTPStatusError: For HTTP errors.
            TimeoutException: If the request times out.
            RequestError: For network or other request-related errors.

        """
        self.logger.debug(
            "Sending request",
            extra={
                "method": method,
                "url": f"{self.base_url}/{url}",
                "params": params,
                "headers": headers,
                "attempt": attempt,
            },
        )
        return await self.client.request(method=method, url=url, params=params, headers=headers)

    def _handle_http_status_error(
        self, e: HTTPStatusError, method: str, url: str, attempt: int
    ) -> None:
        """Handle and log HTTP status-related errors."""
        self.logger.error(
            "HTTP status error occurred",
            extra={
                "method": method,
                "url": url,
                "status_code": e.response.status_code,
                "text": e.response.text[:500],  # Log only part of body if large
                "attempt": attempt,
            },
        )

    def _handle_timeout_error(
        self, e: TimeoutException, method: str, url: str, attempt: int
    ) -> None:
        """Handle and log request timeout errors."""
        self.logger.error(
            "Request timed out",
            extra={
                "method": method,
                "url": url,
                "timeout": self.timeout,
                "attempt": attempt,
            },
        )

    def _handle_request_error(self, e: RequestError, method: str, url: str, attempt: int) -> None:
        """Handle and log network-related request errors."""
        self.logger.error(
            "Network error occurred",
            extra={
                "method": method,
                "url": url,
                "error": str(e),
                "attempt": attempt,
            },
        )

    def _handle_value_error(self, e: ValueError, method: str, url: str) -> None:
        """Handle and log ValueErrors (e.g., JSON parse errors)."""
        self.logger.error(
            "Value error occurred while processing the response",
            extra={"error": str(e), "method": method, "url": url},
        )

    async def _handle_response(self, response: httpx.Response, model: type[R]) -> R:
        """Validate and parse the HTTP response into a Pydantic model.

        Args:
            response: The `httpx.Response` object to parse.
            model: A Pydantic model class used to validate and parse the JSON data.

        Returns:
            An instance of `model` created from the response data.

        Raises:
            ApiClientError: If validation fails or data is malformed.

        """
        try:
            data = response.json()
            return model.model_validate(data)
        except ValidationError as e:
            self.logger.error(
                "Validation error occurred while parsing response",
                extra={"error": e.errors(), "raw_response": response.text[:500]},
            )
            raise ApiClientError("Invalid data received from API") from e
        except ValueError as e:
            self.logger.error(
                "JSON decoding error occurred",
                extra={"error": str(e), "raw_response": response.text[:500]},
            )
            raise ApiClientError("Failed to decode JSON response") from e
