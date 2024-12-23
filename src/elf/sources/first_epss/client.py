"""API client for interacting with the FIRST Exploit Prediction Scoring System (EPSS) API.

The `FirstEpssApiClient` provides high-level methods to query EPSS scores and metadata
for vulnerabilities identified by CVE IDs. It supports various output formats (JSON, CSV)
and offers flexible filtering, pagination, and robust error handling.

**Key Features:**
    - Fetch EPSS scores for single or multiple CVEs in JSON or CSV format.
    - Support for advanced filtering: date ranges, score thresholds, percentiles, and query strings.
    - Automatic pagination for large result sets.
    - Integration with Pydantic models for structured validation and type safety.
    - Robust logging for monitoring and troubleshooting.

EPSS API Reference:
    https://www.first.org/epss/
"""

from __future__ import annotations

import csv
import gzip
import logging
from collections.abc import AsyncGenerator
from io import BytesIO, StringIO
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from elf.core.base_api_client import BaseApiClient
from elf.core.exceptions import (
    ApiClientDataError,
    ApiClientError,
    ApiClientNetworkError,
    ApiClientTimeoutError,
)
from elf.sources.first_epss.models import (
    FirstEpssOrderOption,
    FirstEpssScoreResponse,
)


def _alias_generator(field_name: str) -> str:
    """Convert field names from snake_case to kebab-case."""
    return field_name.replace("_", "-")


class BaseRequestParams(BaseModel):
    """Base model for EPSS API request parameters."""

    date: str | None = Field(None, description="Specific date filter (YYYY-MM-DD).")
    days: int | None = Field(None, description="Number of days from today to filter.")
    epss_gt: float | None = Field(None, ge=0.0, le=1.0, description="Minimum EPSS score threshold.")
    epss_lt: float | None = Field(None, ge=0.0, le=1.0, description="Maximum EPSS score threshold.")
    percentile_gt: float | None = Field(
        None, ge=0.0, le=100.0, description="Minimum percentile threshold."
    )
    percentile_lt: float | None = Field(
        None, ge=0.0, le=100.0, description="Maximum percentile threshold."
    )
    q: str | None = Field(None, description="Query string for additional filtering.")
    order: FirstEpssOrderOption | None = Field(
        None, description="Specify ordering of results (e.g., `!epss`)."
    )
    scope: Literal["time-series"] | None = Field(
        None, description='Define the query scope (e.g., "time-series").'
    )

    model_config = ConfigDict(
        alias_generator=_alias_generator,
        populate_by_name=True,
    )


class FirstEpssApiClient(BaseApiClient):
    """Client for interacting with the FIRST EPSS API.

    Provides methods to query EPSS scores (JSON/CSV), apply filters, paginate results, and handle errors.
    See https://www.first.org/epss/api for full documentation.

    Example:
        >>> from elf.sources.first_epss.client import FirstEpssApiClient
        >>> async with FirstEpssApiClient() as client:
        ...     scores = await client.get_cves(["CVE-2022-27225", "CVE-2021-34527"])
        ...     print(scores.total)

    """

    DEFAULT_BASE_URL = "https://api.first.org/data/v1"

    def __init__(
        self,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        retries: int = 3,
        backoff_factor: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize the EPSS API client.

        Args:
            timeout: Timeout for HTTP requests in seconds (default: 30.0).
            headers: Additional HTTP headers for all requests.
            retries: Number of retry attempts for failed requests (default: 3).
            backoff_factor: Exponential backoff factor between retries (default: 0.5).
            client: Custom `httpx.AsyncClient` for dependency injection (optional).

        Example:
            >>> client = FirstEpssApiClient(timeout=15.0, retries=5)

        """
        super().__init__(
            base_url=self.DEFAULT_BASE_URL,
            timeout=timeout,
            headers=headers,
            retries=retries,
            backoff_factor=backoff_factor,
            client=client,
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    async def _parse_response(self, response: httpx.Response) -> FirstEpssScoreResponse:
        """Parse the HTTP response into a `FirstEpssScoreResponse` model.

        Args:
            response: The HTTP response to parse.

        Returns:
            A `FirstEpssScoreResponse` instance containing EPSS data.

        Raises:
            ApiClientDataError: If validation fails or the response is malformed.

        """
        # Capture a small snippet of the raw response for troubleshooting if needed
        raw_text_snippet = response.text[:500]

        try:
            return await self._handle_response(response, FirstEpssScoreResponse)
        except ApiClientDataError as e:
            self.logger.error(
                "Validation error while parsing EPSS JSON response",
                extra={"error": str(e), "raw_response_snippet": raw_text_snippet},
            )
            raise

    def _prepare_params(
        self,
        *,
        cve_ids: list[str] | None = None,
        cve_id: str | None = None,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        # Global parameters
        offset: int | None = None,
        limit: int | None = None,
        envelope: bool = False,
        pretty: bool = False,
    ) -> dict[str, Any]:
        """Prepare query parameters for EPSS API requests, including global parameters.

        If both `cve_ids` and `cve_id` are provided, `cve_ids` take precedence.
        If no filter parameters are set (date, days, epss_gt, etc.), then no `BaseRequestParams` is created.

        Args:
            cve_ids: A list of CVE IDs to query.
            cve_id: A single CVE ID to query.
            date: Specific date filter (YYYY-MM-DD).
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: Query string for additional filtering.
            order: Specify ordering of results (e.g., `!epss`).
            scope: Define the query scope (e.g., "time-series").
            offset: Offset for paging (global parameter).
            limit: Limit for paging (global parameter).
            envelope: Whether to wrap response in an envelope (global parameter).
            pretty: Whether to pretty-print JSON (global parameter).

        Returns:
            A dictionary of query parameters suitable for the EPSS API.

        """
        params: dict[str, Any] = {}

        # Handle CVE parameters with priority: cve_ids > cve_id
        if cve_ids:
            params["cve"] = ",".join(cve_ids)
        elif cve_id:
            params["cve"] = cve_id

        # Only create a request model if any filtering fields are provided
        if any(
            [
                date,
                days,
                epss_gt,
                epss_lt,
                percentile_gt,
                percentile_lt,
                q,
                order,
                scope,
            ]
        ):
            try:
                request_params = BaseRequestParams(
                    date=date,
                    days=days,
                    epss_gt=epss_gt,
                    epss_lt=epss_lt,
                    percentile_gt=percentile_gt,
                    percentile_lt=percentile_lt,
                    q=q,
                    order=order,
                    scope=scope,
                )
            except ValidationError as ve:
                self.logger.error(
                    "Validation error while preparing EPSS API request parameters",
                    extra={"error": str(ve)},
                )
                raise ApiClientError(f"Invalid parameters: {ve}") from ve
            # model_dump filters out None fields and applies aliases
            params.update(request_params.model_dump(by_alias=True, exclude_none=True))

        # Global parameters
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if envelope:
            params["envelope"] = "true"
        if pretty:
            params["pretty"] = "true"

        return params

    # -----------------------------------------------------------------------------
    #   MULTIPLE CVEs
    # -----------------------------------------------------------------------------

    async def get_cves(
        self,
        *,
        cve_ids: list[str] | None = None,
        cve_id: str | None = None,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        offset: int | None = None,
        limit: int | None = None,
        envelope: bool = False,
        pretty: bool = False,
    ) -> FirstEpssScoreResponse:
        """Retrieve EPSS scores for multiple CVEs in JSON format.

        This method acts as a unified interface (`get_cves`) to fetch scores in JSON format,
        supporting all filtering and global parameters.

        Args:
            cve_ids: A list of CVE IDs to query.
            cve_id: A single CVE ID to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Filter by a number of days from today.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            scope: Define the query scope (e.g., "time-series").
            offset: Offset for pagination (global).
            limit: Limit for pagination (global).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global).

        Returns:
            A `FirstEpssScoreResponse` with parsed EPSS scores and metadata.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        Example:
            >>> scores = await client.get_cves(
            ...     cve_ids=["CVE-2022-27225", "CVE-2021-34527"],
            ...     epss_gt=0.5, order=OrderOption.PERCENTILE, limit=5
            ... )
            >>> print(len(scores.data))

        """
        endpoint = "/epss"
        params = self._prepare_params(
            cve_ids=cve_ids,
            cve_id=cve_id,
            date=date,
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            scope=scope,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

        self.logger.debug(
            "Retrieving multiple EPSS scores (JSON)",
            extra={"endpoint": endpoint, "params": params},
        )

        try:
            response = await self._request("GET", endpoint, params=params, response_format="json")
            return await self._parse_response(response)
        except httpx.TimeoutException as e:
            self.logger.error(
                "Timeout occurred while fetching multiple CVEs",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
        except httpx.RequestError as e:
            self.logger.error(
                "Network error occurred while fetching multiple CVEs",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    async def get_scores_json(
        self,
        cve_ids: list[str],
        *,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        offset: int | None = None,
        limit: int | None = None,
        envelope: bool = False,
        pretty: bool = False,
    ) -> FirstEpssScoreResponse:
        """Retrieve EPSS scores for multiple CVEs in JSON format.

        Args:
            cve_ids: A list of CVE IDs to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Filter by a number of days from today.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            scope: Define the query scope (e.g., "time-series").
            offset: Offset for pagination (global).
            limit: Limit for pagination (global).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global).

        Returns:
            A `FirstEpssScoreResponse` with parsed EPSS scores and metadata.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        return await self.get_cves(
            cve_ids=cve_ids,
            date=date,
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            scope=scope,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

    async def get_scores_csv(
        self,
        cve_ids: list[str],
        *,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        offset: int | None = None,
        limit: int | None = None,
        envelope: bool = False,
        pretty: bool = False,
    ) -> str:
        """Retrieve EPSS scores for multiple CVEs in CSV format with optional filters.

        Args:
            cve_ids: A list of CVE IDs to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Filter by a number of days from today.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            scope: Define the query scope (e.g., "time-series").
            offset: Offset for pagination (global).
            limit: Limit for pagination (global).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global).

        Returns:
            A `str` containing CSV-formatted EPSS data.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        endpoint = "/epss.csv"
        params = self._prepare_params(
            cve_ids=cve_ids,
            date=date,
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            scope=scope,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

        self.logger.debug(
            "Retrieving multiple EPSS scores (CSV)",
            extra={"endpoint": endpoint, "params": params},
        )

        try:
            response = await self._request("GET", endpoint, params=params, response_format="csv")
            return response.text
        except httpx.TimeoutException as e:
            self.logger.error(
                "Timeout occurred while fetching multiple CVEs in CSV format",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
        except httpx.RequestError as e:
            self.logger.error(
                "Network error occurred while fetching multiple CVEs in CSV format",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    # -----------------------------------------------------------------------------
    #   SINGLE CVE
    # -----------------------------------------------------------------------------

    async def get_score_json(
        self,
        cve_id: str,
        *,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        offset: int | None = None,
        limit: int | None = None,
        envelope: bool = False,
        pretty: bool = False,
    ) -> FirstEpssScoreResponse:
        """Retrieve EPSS score for a single CVE in JSON format.

        Similar parameters to `get_scores_json`, but for a single CVE.

        Args:
            cve_id: The CVE ID to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Filter by a number of days from today.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            scope: Define the query scope (e.g., "time-series").
            offset: Offset for pagination (global).
            limit: Limit for pagination (global).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global).

        Returns:
            A `FirstEpssScoreResponse` instance.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        return await self.get_cves(
            cve_id=cve_id,
            date=date,
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            scope=scope,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

    async def get_score_csv(
        self,
        cve_id: str,
        *,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        offset: int | None = None,
        limit: int | None = None,
        envelope: bool = False,
        pretty: bool = False,
    ) -> str:
        """Retrieve EPSS score for a single CVE in CSV format.

        Args:
            cve_id: The CVE ID to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Filter by a number of days from today.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            scope: Define the query scope (e.g., "time-series").
            offset: Offset for pagination (global).
            limit: Limit for pagination (global).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global).

        Returns:
            A `str` containing CSV-formatted EPSS data.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        endpoint = "/epss.csv"
        params = self._prepare_params(
            cve_id=cve_id,
            date=date,
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            scope=scope,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

        self.logger.debug(
            "Retrieving single EPSS score (CSV)",
            extra={"endpoint": endpoint, "params": params},
        )

        try:
            response = await self._request("GET", endpoint, params=params, response_format="csv")
            return response.text
        except httpx.TimeoutException as e:
            self.logger.error(
                "Timeout occurred while fetching single CVE in CSV format",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
        except httpx.RequestError as e:
            self.logger.error(
                "Network error occurred while fetching single CVE in CSV format",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    # -----------------------------------------------------------------------------
    #   RECENT CVEs
    # -----------------------------------------------------------------------------

    async def get_recent_cves(
        self,
        *,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        offset: int | None = None,
        limit: int = 100,  # Default to 100
        envelope: bool = False,
        pretty: bool = False,
    ) -> FirstEpssScoreResponse:
        """Retrieve recent EPSS scores in JSON format (default limit=100).

        Args:
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            offset: Offset for pagination (global).
            limit: How many CVEs to return (default: 100).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global).

        Returns:
            A `FirstEpssScoreResponse` with recent EPSS scores and metadata.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        endpoint = "/epss"
        params = self._prepare_params(
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

        self.logger.debug(
            "Retrieving most recent EPSS scores (JSON)",
            extra={"endpoint": endpoint, "params": params},
        )

        try:
            response = await self._request("GET", endpoint, params=params, response_format="json")
            return await self._parse_response(response)
        except httpx.TimeoutException as e:
            self.logger.error(
                "Timeout occurred while fetching recent CVEs",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
        except httpx.RequestError as e:
            self.logger.error(
                "Network error occurred while fetching recent CVEs",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    async def get_recent_cves_csv(
        self,
        *,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        offset: int | None = None,
        limit: int = 100,  # Default to 100
        envelope: bool = False,
        pretty: bool = False,
    ) -> str:
        """Retrieve recent EPSS scores in CSV format (default limit=100).

        Args:
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering (e.g., OrderOption.EPS).
            offset: Offset for pagination (global).
            limit: How many CVEs to return (default: 100).
            envelope: Wrap response in an envelope (global).
            pretty: Pretty-print JSON output (global, typically ignored in CSV responses).

        Returns:
            CSV-formatted `str` containing recent EPSS scores.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        endpoint = "/epss.csv"
        params = self._prepare_params(
            days=days,
            epss_gt=epss_gt,
            epss_lt=epss_lt,
            percentile_gt=percentile_gt,
            percentile_lt=percentile_lt,
            q=q,
            order=order,
            offset=offset,
            limit=limit,
            envelope=envelope,
            pretty=pretty,
        )

        self.logger.debug(
            "Retrieving most recent EPSS scores (CSV)",
            extra={"endpoint": endpoint, "params": params},
        )

        try:
            response = await self._request("GET", endpoint, params=params, response_format="csv")
            return response.text
        except httpx.TimeoutException as e:
            self.logger.error(
                "Timeout occurred while fetching recent CVEs in CSV format",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
        except httpx.RequestError as e:
            self.logger.error(
                "Network error occurred while fetching recent CVEs in CSV format",
                extra={"error": str(e), "endpoint": endpoint},
            )
            raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    # -----------------------------------------------------------------------------
    #   PAGINATED METHODS (JSON & CSV)
    # -----------------------------------------------------------------------------

    async def get_scores_paginated_json(
        self,
        *,
        cve_ids: list[str] | None = None,
        cve_id: str | None = None,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        limit_per_request: int = 100,
        max_records: int | None = None,
        offset: int = 0,
        envelope: bool = False,
        pretty: bool = False,
    ) -> AsyncGenerator[FirstEpssScoreResponse, None]:
        """Fetch paginated EPSS scores in JSON format, automatically handling pagination.

        Yields `FirstEpssScoreResponse` instances page by page until no more data or `max_records` is reached.

        Args:
            cve_ids: Optional CVE IDs to query.
            cve_id: Optional single CVE ID to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: Query string for additional filtering.
            order: Specify ordering of results (e.g., `!epss`).
            scope: Define the query scope (e.g., "time-series").
            limit_per_request: Number of records to request per page.
            max_records: Maximum total records to fetch before stopping.
            offset: Starting offset.
            envelope: Wrap response in an envelope (global parameter).
            pretty: Pretty-print JSON (global parameter).

        Yields:
            `FirstEpssScoreResponse` objects for each page of results.

        """
        current_offset = offset
        total_records_fetched = 0

        while True:
            params = self._prepare_params(
                cve_ids=cve_ids,
                cve_id=cve_id,
                date=date,
                days=days,
                epss_gt=epss_gt,
                epss_lt=epss_lt,
                percentile_gt=percentile_gt,
                percentile_lt=percentile_lt,
                q=q,
                order=order,
                scope=scope,
                offset=current_offset,
                limit=limit_per_request,
                envelope=envelope,
                pretty=pretty,
            )

            self.logger.debug(
                "Fetching paginated EPSS scores (JSON)",
                extra={"offset": current_offset, "limit": limit_per_request, "params": params},
            )

            try:
                response = await self._request(
                    "GET", "/epss", params=params, response_format="json"
                )
                epss_response = await self._parse_response(response)
                yield epss_response

                batch_count = len(epss_response.data)
                total_records_fetched += batch_count
                current_offset += limit_per_request

                self.logger.debug(f"Fetched {batch_count} records (Total: {total_records_fetched})")

                # Pagination stop conditions
                if max_records is not None and total_records_fetched >= max_records:
                    self.logger.debug(f"Reached maximum record limit: {total_records_fetched}")
                    break
                if batch_count < limit_per_request:
                    self.logger.debug("No more records to fetch.")
                    break
                if epss_response.total <= total_records_fetched:
                    self.logger.debug(f"Fetched all available records: {total_records_fetched}")
                    break

            except httpx.TimeoutException as e:
                self.logger.error(
                    "Timeout occurred during paginated JSON fetch",
                    extra={"error": str(e), "endpoint": "/epss"},
                )
                raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
            except httpx.RequestError as e:
                self.logger.error(
                    "Network error occurred during paginated JSON fetch",
                    extra={"error": str(e), "endpoint": "/epss"},
                )
                raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    async def get_scores_paginated_csv(
        self,
        *,
        cve_ids: list[str] | None = None,
        cve_id: str | None = None,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: FirstEpssOrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        limit_per_request: int = 100,
        max_records: int | None = None,
        offset: int = 0,
        envelope: bool = False,
        pretty: bool = False,
    ) -> AsyncGenerator[str, None]:
        """Fetch paginated EPSS scores in CSV format from the API.

        Yields CSV-formatted result pages as strings until no more data or `max_records` is reached.

        Args:
            cve_ids: Optional CVE IDs to query.
            cve_id: Optional single CVE ID to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: Query string for additional filtering.
            order: Specify ordering of results (e.g., `!epss`).
            scope: Define the query scope (e.g., "time-series").
            limit_per_request: Number of records per page.
            max_records: Maximum total records to fetch before stopping.
            offset: Starting offset.
            envelope: Wrap response in an envelope (global parameter).
            pretty: Pretty-print JSON (global parameter, typically ignored in CSV responses).

        Yields:
            `str` CSV-formatted data for each page.

        """
        current_offset = offset
        total_records_fetched = 0

        while True:
            params = self._prepare_params(
                cve_ids=cve_ids,
                cve_id=cve_id,
                date=date,
                days=days,
                epss_gt=epss_gt,
                epss_lt=epss_lt,
                percentile_gt=percentile_gt,
                percentile_lt=percentile_lt,
                q=q,
                order=order,
                scope=scope,
                offset=current_offset,
                limit=limit_per_request,
                envelope=envelope,
                pretty=pretty,
            )

            self.logger.debug(
                "Fetching paginated EPSS scores (CSV)",
                extra={"offset": current_offset, "limit": limit_per_request, "params": params},
            )

            try:
                response = await self._request(
                    "GET", "/epss.csv", params=params, response_format="csv"
                )
                yield response.text

                # Count lines to determine batch size (subtract 1 for header)
                csv_reader = csv.reader(StringIO(response.text))
                batch_count = sum(1 for _ in csv_reader) - 1

                if batch_count < 0:
                    batch_count = 0  # Handle cases with no data

                total_records_fetched += batch_count
                current_offset += limit_per_request

                self.logger.debug(f"Fetched {batch_count} records (Total: {total_records_fetched})")

                # Stop if:
                if max_records is not None and total_records_fetched >= max_records:
                    self.logger.debug(f"Reached maximum record limit: {total_records_fetched}")
                    break
                if batch_count < limit_per_request:
                    self.logger.debug("No more records to fetch.")
                    break

                # Because CSV doesn't always include a "total" field, we rely solely on batch_count.

            except httpx.TimeoutException as e:
                self.logger.error(
                    "Timeout occurred during paginated CSV fetch",
                    extra={"error": str(e), "endpoint": "/epss.csv"},
                )
                raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
            except httpx.RequestError as e:
                self.logger.error(
                    "Network error occurred during paginated CSV fetch",
                    extra={"error": str(e), "endpoint": "/epss.csv"},
                )
                raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    # -----------------------------------------------------------------------------
    #   DOWNLOAD FULL CSV FOR A SPECIFIC DATE
    # -----------------------------------------------------------------------------

    async def download_full_csv_for_date(
        self,
        date: str,
    ) -> bytes:
        """Download the full EPSS CSV file for a specific date.

        Args:
            date (str): The specific date in 'YYYY-MM-DD' format.

        Returns:
            bytes: The raw CSV file content as bytes.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response data is malformed.

        """
        url = f"https://epss.cyentia.com/epss_scores-{date}.csv.gz"
        self.logger.debug("Downloading full CSV for date", extra={"url": url})

        try:
            # Directly use httpx to fetch binary data
            response = await self.client.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.content
        except httpx.HTTPStatusError as e:
            self.logger.error(
                "HTTP error while downloading full CSV for date",
                extra={"error": str(e), "url": url},
            )
            raise ApiClientError(f"HTTP error occurred: {e}") from e
        except httpx.TimeoutException as e:
            self.logger.error(
                "Timeout while downloading full CSV for date",
                extra={"error": str(e), "url": url},
            )
            raise ApiClientTimeoutError(f"Timeout error occurred: {e}") from e
        except httpx.RequestError as e:
            self.logger.error(
                "Network error while downloading full CSV for date",
                extra={"error": str(e), "url": url},
            )
            raise ApiClientNetworkError(f"Network error occurred: {e}") from e

    # -----------------------------------------------------------------------------
    #   DOWNLOAD AND DECOMPRESS FULL CSV FOR A SPECIFIC DATE (Optional)
    # -----------------------------------------------------------------------------

    async def download_and_decompress_full_csv_for_date(
        self,
        date: str,
    ) -> str:
        """Download and decompress the full EPSS CSV file for a specific date.

        Args:
            date (str): The specific date in 'YYYY-MM-DD' format.

        Returns:
            str: The decompressed CSV file content as a string.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If decompression fails.

        """
        csv_gz_data = await self.download_full_csv_for_date(date)
        self.logger.debug("Decompressing downloaded CSV data", extra={"date": date})
        try:
            with gzip.GzipFile(fileobj=BytesIO(csv_gz_data)) as gz:
                decompressed = gz.read().decode("utf-8")
            return decompressed
        except OSError as e:
            self.logger.error(
                "Failed to decompress CSV data",
                extra={"error": str(e), "date": date},
            )
            raise ApiClientDataError(f"Failed to decompress CSV data for date {date}") from e
        except UnicodeDecodeError as e:
            self.logger.error(
                "Failed to decode decompressed CSV data",
                extra={"error": str(e), "date": date},
            )
            raise ApiClientDataError(f"Failed to decode CSV data for date {date}") from e
