"""API client for interacting with the NIST National Vulnerability Database (NVD) API.

The `NistNvdApiClient` provides a high-level interface to:
- Fetch details for a specific CVE by its ID.
- Search for CVEs using a wide range of filters (CPEs, CVSS scores, tags, etc.).
- Retrieve CVE change history with optional filters and pagination.
- Parse responses into strongly typed Pydantic models (`NistNvdCveResponse`, `NistNvdCveHistoryResponse`) for structured validation.

**Key Features:**
    - Fetch detailed information for a specific CVE by ID.
    - Support searching CVEs with various filters and sorting options.
    - Retrieve CVE change history with optional filters and pagination.
    - Utilize Pydantic models for validated, structured responses.
    - Pagination and date-range filtering best practices.
    - Comprehensive logging and error handling for robust UX.
    - Supports rate limits and optional API keys for higher rate limits.

**NVD API Reference:**
    - General: https://nvd.nist.gov/developers
    - Vulnerabilities (CVE) API: https://nvd.nist.gov/developers/vulnerabilities

**Rate Limits and API Keys:**
- Without an API key: 5 requests per rolling 30 seconds.
- With an API key: 50 requests per rolling 30 seconds.
To obtain an API key, visit https://nvd.nist.gov/developers/request-an-api-key and set `api_key` upon initialization.

**Best Practices:**
- Use date ranges (`lastModStartDate`, `lastModEndDate`, `pubStartDate`, `pubEndDate`) to limit results.
- Consider sleeping (~6 seconds) between requests to avoid hitting rate limits.
- For enterprise scale, coordinate a single API key and a single requestor to sync data among users.

**Example:**
    >>> from elf.sources.nist_nvd.client import NistNvdApiClient
    >>> async with NistNvdApiClient(api_key="YOUR_API_KEY") as client:
    ...     cve_data = await client.get_cve("CVE-2021-34527")
    ...     print(cve_data.vulnerabilities[0].cve.id)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any, Literal, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from elf.core.base_api_client import BaseApiClient
from elf.core.exceptions import ApiClientError
from elf.sources.nist_nvd.models import (
    NistNvdCveHistoryResponse,
    NistNvdCveResponse,
)

M = TypeVar("M", bound=BaseModel)


class NistNvdApiClient(BaseApiClient):
    """Client for interacting with the NIST National Vulnerability Database (NVD) API.

    Allows retrieving CVE details, searching CVEs, and retrieving CVE history with filtering
    and pagination. Responses are validated and parsed into Pydantic models.

    Attributes:
        DEFAULT_BASE_URL (str): The default base URL for the NVD API.
        api_key (str | None): An optional API key for increased rate limits.

    """

    DEFAULT_BASE_URL: str = "https://services.nvd.nist.gov/rest/json"

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        retries: int = 3,
        backoff_factor: float = 0.5,
        client: httpx.AsyncClient | None = None,
        api_key: str | None = None,
    ) -> None:
        """Initialize the NVD API client.

        Args:
            timeout: Timeout for HTTP requests in seconds.
            headers: Additional HTTP headers for all requests.
            retries: Number of retry attempts for failed requests.
            backoff_factor: Exponential backoff factor between retries.
            client: Optional custom `httpx.AsyncClient` instance.
            api_key: Optional NVD API key for increased rate limits.

        """
        super().__init__(
            base_url=self.DEFAULT_BASE_URL,
            timeout=timeout,
            headers=headers,
            retries=retries,
            backoff_factor=backoff_factor,
            client=client,
        )
        self.api_key = api_key

    def _format_datetime(self, dt: datetime) -> str:
        """Format a datetime object to the NVD API's expected ISO 8601 format with microseconds and UTC.

        Args:
            dt: The datetime object to format.

        Returns:
            A string with ISO 8601 format ending in 'Z' for UTC.

        """
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    async def _parse_response(
        self, response: httpx.Response
    ) -> NistNvdCveResponse | NistNvdCveHistoryResponse:
        """Parse the HTTP response into the appropriate Pydantic model.

        The model chosen is based on the presence of 'vulnerabilities' or 'cveChanges' keys in the JSON.

        Args:
            response: The HTTP response from the NVD API.

        Returns:
            An instance of `NistNvdCveResponse` or `NistNvdCveHistoryResponse`.

        Raises:
            ApiClientError: If the response format is unknown or validation fails.

        """
        # Keep a snippet of the response text for debugging if unexpected data occurs
        raw_text_snippet = response.text[:500]

        try:
            data = response.json()
            if "vulnerabilities" in data:
                return NistNvdCveResponse.model_validate(data)
            elif "cveChanges" in data:
                return NistNvdCveHistoryResponse.model_validate(data)
            else:
                self.logger.error(
                    "Unknown response format",
                    extra={
                        "response_keys": list(data.keys()),
                        "raw_response_snippet": raw_text_snippet,
                    },
                )
                raise ApiClientError("Unknown response format from NVD API.")
        except ValidationError as e:
            self.logger.error(
                "Validation error while parsing NVD response",
                extra={
                    "errors": e.errors(),
                    "raw_response_snippet": raw_text_snippet,
                },
            )
            raise ApiClientError("Invalid data received from NVD API") from e
        except ValueError as e:
            self.logger.error(
                "JSON decoding error",
                extra={
                    "error": str(e),
                    "raw_response_snippet": raw_text_snippet,
                },
            )
            raise ApiClientError("Failed to decode JSON response") from e

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"],
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        response_format: Literal["json", "csv"] = "json",
    ) -> httpx.Response:
        """Perform an HTTP request, injecting the API key if available.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: API endpoint relative to the base URL.
            params: Query parameters for the request.
            headers: Additional request headers.
            response_format: Expected response format, defaults to JSON.

        Returns:
            The HTTP response object.

        Raises:
            ApiClientError or related exceptions as handled by the BaseApiClient.

        """
        request_headers = headers or {}
        if self.api_key:
            request_headers["apiKey"] = self.api_key

        return await super()._request(
            method,
            endpoint,
            params=params,
            headers=request_headers,
            response_format=response_format,
        )

    async def get_cve(self, cve_id: str) -> NistNvdCveResponse:
        """Retrieve detailed information for a specific CVE by its ID.

        Args:
            cve_id: The CVE identifier, e.g., "CVE-2021-34527".

        Returns:
            A `NistNvdCveResponse` containing CVE details.

        Raises:
            ApiClientError: If parsing or retrieval fails.

        Example:
            >>> async with NistNvdApiClient(api_key="YOUR_API_KEY") as client:
            ...     cve_data = await client.get_cve("CVE-2021-34527")
            ...     print(cve_data.vulnerabilities[0].cve.id)

        """
        endpoint = "/cves/2.0"
        params = {"cveId": cve_id}

        self.logger.debug(
            "Retrieving CVE details",
            extra={"cve_id": cve_id, "endpoint": endpoint, "params": params},
        )
        response = await self._request("GET", endpoint, params=params)
        parsed = await self._parse_response(response)
        if isinstance(parsed, NistNvdCveResponse):
            return parsed
        raise ApiClientError("Unexpected response type for CVE details.")

    async def search_cves(
        self,
        *,
        cpe_name: str | None = None,
        cve_id: str | None = None,
        cve_tag: str | None = None,
        cvss_v2_metrics: str | None = None,
        cvss_v2_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        cvss_v3_metrics: str | None = None,
        cvss_v3_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        cvss_v4_metrics: str | None = None,
        cvss_v4_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        cwe_id: str | None = None,
        has_cert_alerts: bool | None = None,
        has_cert_notes: bool | None = None,
        has_kev: bool | None = None,
        has_oval: bool | None = None,
        is_vulnerable: bool | None = None,
        keyword_exact_match: bool | None = None,
        keyword_search: str | None = None,
        last_mod_start_date: datetime | None = None,
        last_mod_end_date: datetime | None = None,
        no_rejected: bool | None = None,
        pub_start_date: datetime | None = None,
        pub_end_date: datetime | None = None,
        results_per_page: int = 100,
        start_index: int = 0,
        source_identifier: str | None = None,
        version_end: str | None = None,
        version_end_type: Literal["inclusive", "exclusive"] | None = None,
        version_start: str | None = None,
        version_start_type: Literal["inclusive", "exclusive"] | None = None,
        virtual_match_string: str | None = None,
    ) -> AsyncGenerator[NistNvdCveResponse, None]:
        """Search for CVEs using various filters with optional pagination.

        This method interfaces directly with the NVD CVE API, allowing you to filter by multiple parameters
        such as CPE names, CVSS scores, CWE IDs, keyword searches, date ranges, and more. The NVD enforces
        offset-based pagination (via `startIndex` and `resultsPerPage`) to return data in manageable chunks.
        Utilize date filters and pagination best practices to efficiently keep your data synchronized with NVD.

        Refer to https://nvd.nist.gov/developers/vulnerabilities for detailed parameter usage and best practices.

        Args:
            cpe_name: Filter by a specific CPE name (e.g., `cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*`).
            cve_id: Filter by a specific CVE ID (e.g., "CVE-2021-34527").
            cve_tag: Filter by a CVE tag (e.g., "disputed").
            cvss_v2_metrics: Filter by a CVSS v2 vector string.
            cvss_v2_severity: Filter by CVSS v2 severity (LOW, MEDIUM, HIGH).
            cvss_v3_metrics: Filter by a CVSS v3 vector string.
            cvss_v3_severity: Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL).
            cvss_v4_metrics: Filter by a CVSS v4 vector string.
            cvss_v4_severity: Filter by CVSS v4 severity (LOW, MEDIUM, HIGH, CRITICAL).
            cwe_id: Filter by a specific CWE-ID (e.g., "CWE-287").
            has_cert_alerts: Filter CVEs that contain a US-CERT technical alert.
            has_cert_notes: Filter CVEs that contain a CERT/CC Vulnerability Note.
            has_kev: Filter CVEs in the CISA KEV Catalog.
            has_oval: Filter CVEs that contain OVAL records.
            is_vulnerable: Filter only CVEs where `cpeName` is considered vulnerable.
            keyword_exact_match: If True, `keywordSearch` must match the phrase exactly.
            keyword_search: Filter by keyword(s) in the CVE description.
            last_mod_start_date: Start of last modification date/time range.
            last_mod_end_date: End of last modification date/time range.
            no_rejected: If True, exclude CVEs with "REJECT" or "Rejected" status.
            pub_start_date: Start of initial publication date/time range.
            pub_end_date: End of initial publication date/time range.
            results_per_page: Max CVEs per response page (default: 100, max: 2000).
            start_index: Starting index for pagination (default: 0).
            source_identifier: Filter by source identifier (e.g., "cve@mitre.org").
            version_end: Ending version for version range filters.
            version_end_type: Whether `version_end` is inclusive or exclusive.
            version_start: Starting version for version range filters.
            version_start_type: Whether `version_start` is inclusive or exclusive.
            virtual_match_string: Filters CVEs by CPE Match Criteria more broadly than `cpeName`.

        Yields:
            NistNvdCveResponse pages matching the specified criteria.

        Raises:
            ApiClientError: If a non-recoverable error occurs during the request or parsing.

        Example:
            >>> async for page in client.search_cves(cpe_name="cpe:2.3:o:microsoft:windows_10", cvss_v3_severity="HIGH"):
            ...     for vuln in page.vulnerabilities:
            ...         print(vuln.cve.id)

        """
        endpoint = "/cves/2.0"
        params: dict[str, Any] = {}

        def _set_param(k: str, v: str | int | bool | None) -> None:
            if v is not None:
                params[k] = v

        _set_param("cpeName", cpe_name)
        _set_param("cveId", cve_id)
        _set_param("cveTag", cve_tag)
        _set_param("cvssV2Metrics", cvss_v2_metrics)
        _set_param("cvssV2Severity", cvss_v2_severity)
        _set_param("cvssV3Metrics", cvss_v3_metrics)
        _set_param("cvssV3Severity", cvss_v3_severity)
        _set_param("cvssV4Metrics", cvss_v4_metrics)
        _set_param("cvssV4Severity", cvss_v4_severity)
        _set_param("cweId", cwe_id)
        _set_param(
            "hasCertAlerts",
            "true" if has_cert_alerts else "false" if has_cert_alerts is False else None,
        )
        _set_param(
            "hasCertNotes",
            "true" if has_cert_notes else "false" if has_cert_notes is False else None,
        )
        _set_param("hasKev", "true" if has_kev else "false" if has_kev is False else None)
        _set_param("hasOval", "true" if has_oval else "false" if has_oval is False else None)
        _set_param(
            "isVulnerable",
            "true" if is_vulnerable else "false" if is_vulnerable is False else None,
        )
        _set_param(
            "keywordExactMatch",
            "true" if keyword_exact_match else "false" if keyword_exact_match is False else None,
        )
        _set_param("keywordSearch", keyword_search)

        if last_mod_start_date and last_mod_end_date:
            _set_param("lastModStartDate", self._format_datetime(last_mod_start_date))
            _set_param("lastModEndDate", self._format_datetime(last_mod_end_date))

        _set_param(
            "noRejected", "true" if no_rejected else "false" if no_rejected is False else None
        )

        if pub_start_date and pub_end_date:
            _set_param("pubStartDate", self._format_datetime(pub_start_date))
            _set_param("pubEndDate", self._format_datetime(pub_end_date))

        _set_param("resultsPerPage", str(results_per_page))
        _set_param("startIndex", str(start_index))
        _set_param("sourceIdentifier", source_identifier)
        _set_param("versionEnd", version_end)
        _set_param("versionEndType", version_end_type)
        _set_param("versionStart", version_start)
        _set_param("versionStartType", version_start_type)
        _set_param("virtualMatchString", virtual_match_string)

        self.logger.debug(
            "Searching CVEs",
            extra={
                "endpoint": endpoint,
                "params": {k: v for k, v in params.items() if v is not None},
            },
        )

        async for page in self._paginate_search_cves(endpoint, params, NistNvdCveResponse):
            yield page

    async def get_cve_history_paginated(
        self,
        *,
        cve_id: str | None = None,
        change_start_date: datetime | None = None,
        change_end_date: datetime | None = None,
        event_name: str | None = None,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> AsyncGenerator[NistNvdCveHistoryResponse, None]:
        """Retrieve paginated CVE change history records based on optional filters.

        Args:
            cve_id: Filter by a specific CVE ID.
            change_start_date: Filter by the start date of the change range.
            change_end_date: Filter by the end date of the change range.
            event_name: Filter by a specific event name.
            results_per_page: Number of results returned per page (default: 100).
            start_index: Starting index for pagination (default: 0).

        Yields:
            `NistNvdCveHistoryResponse` pages until all results are exhausted.

        Raises:
            ApiClientError: On invalid responses or pagination issues.

        Example:
            >>> async for page in client.get_cve_history_paginated(
            ...     cve_id="CVE-2021-34527",
            ...     change_start_date=datetime(2023, 1, 1),
            ...     change_end_date=datetime(2023, 6, 1),
            ...     results_per_page=50
            ... ):
            ...     print(page.cve_changes)

        """
        endpoint = "/cvehistory/2.0"
        params: dict[str, Any] = {}

        def _set_param(k: str, v: str | int | bool | None) -> None:
            if v is not None:
                params[k] = v

        _set_param("cveId", cve_id)
        if change_start_date and change_end_date:
            _set_param("changeStartDate", self._format_datetime(change_start_date))
            _set_param("changeEndDate", self._format_datetime(change_end_date))
        _set_param("eventName", event_name)
        _set_param("resultsPerPage", str(results_per_page))
        _set_param("startIndex", str(start_index))

        self.logger.debug(
            "Retrieving CVE history",
            extra={
                "endpoint": endpoint,
                "params": {k: v for k, v in params.items() if v is not None},
            },
        )

        async for page in self._paginate_search_cves(endpoint, params, NistNvdCveHistoryResponse):
            yield page

    async def _paginate_search_cves(
        self,
        endpoint: str,
        params: dict[str, Any],
        model: type[M],
    ) -> AsyncGenerator[M, None]:
        """Handle pagination for CVE search and change history endpoints.

        Continues fetching pages until no more results are available or all are fetched.

        Args:
            endpoint: The API endpoint being queried (e.g., "/cves/2.0").
            params: Query parameters to be sent with each request.
            model: The Pydantic model class to parse responses into.

        Yields:
            Instances of `model` for each page of results.

        Raises:
            ApiClientError: If a request fails or data is malformed.

        """
        current_index = int(params.get("startIndex", 0))
        results_per_page = int(params.get("resultsPerPage") or 100)
        total_results = None

        while True:
            params["startIndex"] = str(current_index)
            params["resultsPerPage"] = str(results_per_page)

            self.logger.debug(
                "Fetching paginated results",
                extra={
                    "startIndex": current_index,
                    "resultsPerPage": results_per_page,
                    "params": params,
                },
            )

            try:
                response = await self._request("GET", endpoint, params=params)
                page: M = await self._handle_response(response, model)
                yield page

                # Determine total results from the first page if available
                if total_results is None:
                    total_results = getattr(page, "total_results", None)
                    if total_results is None:
                        self.logger.warning(
                            "No 'totalResults' in response; assuming single-page result set."
                        )
                        break

                current_index += results_per_page

                if total_results is not None and current_index >= total_results:
                    self.logger.debug("All pages fetched successfully.")
                    break

            except Exception as e:
                self.logger.error(
                    "Error during pagination",
                    extra={"current_index": current_index, "error": str(e)},
                )
                raise ApiClientError(f"Pagination error: {str(e)}") from e
