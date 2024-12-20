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
from collections.abc import AsyncGenerator
from enum import Enum
from io import StringIO
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict

from elf.core.base_api_client import BaseApiClient
from elf.core.exceptions import ApiClientDataError
from elf.sources.first_epss.models import FirstEpssScoreResponse


class OrderOption(str, Enum):
    """Enumeration for ordering options in the EPSS API."""

    EPS = "!epss"
    PERCENTILE = "!percentile"


class BaseRequestParams(BaseModel):
    """Model for request parameters used in EPSS API queries.

    This model ensures parameters are properly aliased and stripped of whitespace.
    Parameters that are None are excluded from the final dictionary.
    """

    date: str | None = None  # format: YYYY-MM-DD
    days: int | None = None
    epss_gt: float | None = None
    epss_lt: float | None = None
    percentile_gt: float | None = None
    percentile_lt: float | None = None
    q: str | None = None
    order: OrderOption | None = None
    scope: Literal["time-series"] | None = None

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=lambda field_name: field_name.replace("_", "-"),
        str_strip_whitespace=True,
    )


class FirstEpssApiClient(BaseApiClient):
    """Client for interacting with the FIRST EPSS API.

    Provides methods to query EPSS scores (JSON/CSV), apply filters, paginate results, and handle errors.

    Attributes:
        DEFAULT_BASE_URL (str): The default base URL for the EPSS API.

    Example:
        >>> from elf.sources.first_epss.client import FirstEpssApiClient
        >>> async with FirstEpssApiClient() as client:
        ...     scores = await client.get_scores_json(["CVE-2022-27225", "CVE-2021-34527"])
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

    async def _parse_response(self, response: httpx.Response) -> FirstEpssScoreResponse:
        """Parse the HTTP response into a `FirstEpssScoreResponse` model.

        Args:
            response: The HTTP response to parse.

        Returns:
            A `FirstEpssScoreResponse` instance containing EPSS data.

        Raises:
            ApiClientDataError: If validation fails or the response is malformed.

        """
        try:
            return await self._handle_response(response, FirstEpssScoreResponse)
        except ApiClientDataError as e:
            self.logger.error(
                "Validation error while parsing EPSS JSON response",
                extra={"error": str(e)},
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
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
    ) -> dict[str, Any]:
        """Prepare query parameters for API requests by building a `BaseRequestParams` model if needed.

        If both `cve_ids` and `cve_id` are provided, `cve_ids` take precedence.
        If no filter parameters are set (date, days, epss_gt, etc.), then no `BaseRequestParams` model is created.

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
            order: Specify ordering of results (e.g., `OrderOption.EPS`).
            scope: Define the query scope (e.g., "time-series").

        Returns:
            A dictionary of query parameters suitable for the EPSS API.

        """
        params: dict[str, Any] = {}

        # Handle CVE parameters with priority: cve_ids > cve_id
        if cve_ids:
            params["cve"] = ",".join(cve_ids)
        elif cve_id:
            params["cve"] = cve_id

        # Only create a request model if any of the filtering fields are provided
        if any([date, days, epss_gt, epss_lt, percentile_gt, percentile_lt, q, order, scope]):
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
            # model_dump filters out None fields and applies aliases
            params.update(request_params.model_dump(by_alias=True, exclude_none=True))

        return params

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
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
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
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").

        Returns:
            A `FirstEpssScoreResponse` with parsed EPSS scores and metadata.

        Raises:
            ApiClientError: For non-recoverable API errors.
            ApiClientTimeoutError: If the request times out.
            ApiClientNetworkError: For network-related errors.
            ApiClientDataError: If the response fails validation.

        Example:
            >>> scores = await client.get_scores_json(
            ...     cve_ids=["CVE-2022-27225", "CVE-2021-34527"],
            ...     epss_gt=0.5, order=OrderOption.PERCENTILE
            ... )
            >>> print(len(scores.data))

        """
        endpoint = "/epss"
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
        )

        self.logger.debug(
            "Retrieving multiple EPSS scores (JSON)", extra={"endpoint": endpoint, "params": params}
        )

        response = await self._request("GET", endpoint, params=params, response_format="json")
        return await self._parse_response(response)

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
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
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
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").

        Returns:
            A `str` containing CSV-formatted EPSS data.

        Raises:
            ApiClientError, ApiClientTimeoutError, ApiClientNetworkError, ApiClientDataError:
                For respective error conditions.

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
        )

        self.logger.debug(
            "Retrieving multiple EPSS scores (CSV)", extra={"endpoint": endpoint, "params": params}
        )

        response = await self._request("GET", endpoint, params=params, response_format="csv")
        return response.text

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
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
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
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").

        Returns:
            A `FirstEpssScoreResponse` instance.

        Raises:
            ApiClientError, ApiClientTimeoutError, ApiClientNetworkError, ApiClientDataError:
                For respective error conditions.

        """
        endpoint = "/epss"
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
        )

        self.logger.debug(
            "Retrieving single EPSS score (JSON)", extra={"endpoint": endpoint, "params": params}
        )

        response = await self._request("GET", endpoint, params=params, response_format="json")
        return await self._parse_response(response)

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
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
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
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").

        Returns:
            A `str` containing CSV-formatted EPSS data.

        Raises:
            ApiClientError, ApiClientTimeoutError, ApiClientNetworkError, ApiClientDataError:
                For respective error conditions.

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
        )

        self.logger.debug(
            "Retrieving single EPSS score (CSV)", extra={"endpoint": endpoint, "params": params}
        )

        response = await self._request("GET", endpoint, params=params, response_format="csv")
        return response.text

    async def get_recent_cves_json(
        self,
        *,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: OrderOption | None = None,
    ) -> FirstEpssScoreResponse:
        """Retrieve recent EPSS scores (first 100 CVEs) in JSON format.

        Args:
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").

        Returns:
            A `FirstEpssScoreResponse` with recent EPSS scores.

        Raises:
            ApiClientError, ApiClientTimeoutError, ApiClientNetworkError, ApiClientDataError:
                For respective error conditions.

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
        )

        self.logger.debug(
            "Retrieving most recent EPSS scores (JSON)",
            extra={"endpoint": endpoint, "params": params},
        )

        response = await self._request("GET", endpoint, params=params, response_format="json")
        return await self._parse_response(response)

    async def get_recent_cves_csv(
        self,
        *,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: OrderOption | None = None,
    ) -> str:
        """Retrieve recent EPSS scores (first 100 CVEs) in CSV format.

        Args:
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering.

        Returns:
            CSV-formatted `str` containing recent EPSS scores.

        Raises:
            ApiClientError, ApiClientTimeoutError, ApiClientNetworkError, ApiClientDataError:
                For respective error conditions.

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
        )

        self.logger.debug(
            "Retrieving most recent EPSS scores (CSV)",
            extra={"endpoint": endpoint, "params": params},
        )

        response = await self._request("GET", endpoint, params=params, response_format="csv")
        return response.text

    async def get_scores_paginated_json(
        self,
        *,
        cve_ids: list[str] | None = None,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        limit_per_request: int = 100,
        max_records: int | None = None,
    ) -> AsyncGenerator[FirstEpssScoreResponse, None]:
        """Fetch paginated EPSS scores in JSON format, automatically handling pagination.

        Yields `FirstEpssScoreResponse` instances page by page.

        Args:
            cve_ids: Optional CVE IDs to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").
            limit_per_request: Number of records to request per page.
            max_records: Maximum total records to fetch before stopping.

        Yields:
            `FirstEpssScoreResponse` objects for each page of results.

        Raises:
            Same exceptions as `get_scores_json`.

        Example:
            >>> async for page in client.get_scores_paginated_json(epss_gt=0.7, limit_per_request=50):
            ...     print(len(page.data))

        """
        current_offset = 0
        total_records_fetched = 0

        while True:
            params: dict[str, Any] = {
                "offset": str(current_offset),
                "limit": str(limit_per_request),
            }
            if cve_ids:
                params["cve"] = ",".join(cve_ids)

            additional_params = self._prepare_params(
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
            params.update(additional_params)

            self.logger.debug(
                "Fetching paginated EPSS scores (JSON)",
                extra={"offset": current_offset, "limit": limit_per_request, "params": params},
            )

            response = await self._request("GET", "/epss", params=params, response_format="json")
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
            if hasattr(epss_response, "total") and epss_response.total <= total_records_fetched:
                self.logger.debug(f"Fetched all available records: {total_records_fetched}")
                break

    async def get_scores_paginated_csv(
        self,
        *,
        cve_ids: list[str] | None = None,
        date: str | None = None,
        days: int | None = None,
        epss_gt: float | None = None,
        epss_lt: float | None = None,
        percentile_gt: float | None = None,
        percentile_lt: float | None = None,
        q: str | None = None,
        order: OrderOption | None = None,
        scope: Literal["time-series"] | None = None,
        limit_per_request: int = 100,
        max_records: int | None = None,
    ) -> AsyncGenerator[str, None]:
        """Fetch paginated EPSS scores in CSV format from the API.

        Yields CSV-formatted result pages as strings.

        Args:
            cve_ids: Optional CVE IDs to query.
            date: Filter by a specific date (YYYY-MM-DD).
            days: Number of days from today to filter.
            epss_gt: Minimum EPSS score threshold.
            epss_lt: Maximum EPSS score threshold.
            percentile_gt: Minimum percentile threshold.
            percentile_lt: Maximum percentile threshold.
            q: A query string for advanced filtering.
            order: Specify result ordering.
            scope: Define the query scope (e.g., "time-series").
            limit_per_request: Number of records per page.
            max_records: Maximum total records to fetch.

        Yields:
            `str` CSV-formatted data for each page.

        Raises:
            ApiClientError, ApiClientTimeoutError, ApiClientNetworkError, ApiClientDataError:
                For respective error conditions.

        Example:
            >>> async for csv_data in client.get_scores_paginated_csv(epss_gt=0.7, limit_per_request=50):
            ...     # Process CSV page

        """
        current_offset = 0
        total_records_fetched = 0

        while True:
            params: dict[str, Any] = {
                "offset": str(current_offset),
                "limit": str(limit_per_request),
            }
            if cve_ids:
                params["cve"] = ",".join(cve_ids)

            additional_params = self._prepare_params(
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
            params.update(additional_params)

            self.logger.debug(
                "Fetching paginated EPSS scores (CSV)",
                extra={"offset": current_offset, "limit": limit_per_request, "params": params},
            )

            response = await self._request("GET", "/epss.csv", params=params, response_format="csv")
            yield response.text

            csv_reader = csv.reader(StringIO(response.text))
            batch_count = sum(1 for _ in csv_reader) - 1  # Subtract header line
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
