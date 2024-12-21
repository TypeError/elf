"""API client for interacting with the CISA Known Exploited Vulnerabilities (KEV) catalog.

This module provides the `CisaKevApiClient`, a high-level client to interact with
the CISA KEV API, enabling retrieval of known exploited vulnerabilities in both
JSON and CSV formats. It also provides a convenient paginated interface for large datasets.

Features:
    - Fetch KEV data in JSON format and parse into typed Pydantic models (`CisaKevCatalog`).
    - Fetch KEV data in CSV format as raw bytes.
    - Paginate through large JSON datasets for efficient processing.

Attribution:
The data utilized here is sourced from the Cybersecurity and Infrastructure Security Agency (CISA).
Please refer to the license at:
    https://www.cisa.gov/sites/default/files/licenses/kev/license.txt

Example:
    >>> from elf.sources.cisa_kev.client import CisaKevApiClient
    >>> async with CisaKevApiClient() as client:
    ...     kev_data = await client.get_kev_json()
    ...     print(kev_data.title, len(kev_data.vulnerabilities))

    # Fetching CSV:
    >>> async with CisaKevApiClient() as client:
    ...     kev_csv = await client.get_kev_csv()
    ...     # `kev_csv` is now raw bytes containing the CSV data.

    # Paginated iteration:
    >>> async with CisaKevApiClient() as client:
    ...     async for chunk in client.get_kev_json_paginated(chunk_size=500):
    ...         print(len(chunk.vulnerabilities))

"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
from pydantic import ValidationError

from elf.core.base_api_client import BaseApiClient
from elf.core.exceptions import ApiClientError
from elf.sources.cisa_kev.models import CisaKevCatalog


class CisaKevApiClient(BaseApiClient):
    """High-level client for interacting with the CISA Known Exploited Vulnerabilities (KEV) catalog.

    This client provides methods to:
    - Retrieve the full KEV catalog as a validated Pydantic model (`CisaKevCatalog`).
    - Retrieve the KEV catalog as CSV (raw bytes).
    - Asynchronously fetch the KEV catalog in paginated chunks for large datasets.

    Attributes:
        DEFAULT_BASE_URL (str): Default base URL for the CISA KEV API.
        logger (logging.Logger): Logger instance for debug and error messages.

    """

    DEFAULT_BASE_URL = "https://www.cisa.gov/sites/default/files"

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> None:
        """Initialize the CISA KEV API client.

        Args:
            timeout: Request timeout in seconds.
            headers: Additional headers for all requests.
            retries: Number of retry attempts for transient request failures.
            backoff_factor: Multiplier for exponential backoff timing.

        """
        super().__init__(
            base_url=self.DEFAULT_BASE_URL,
            timeout=timeout,
            headers=headers,
            retries=retries,
            backoff_factor=backoff_factor,
        )

    async def _parse_response(self, response: httpx.Response) -> CisaKevCatalog:
        """Parse a HTTPX response into a `CisaKevCatalog` model.

        Args:
            response: The HTTP response from the KEV API.

        Returns:
            A fully validated `CisaKevCatalog` model.

        Raises:
            ApiClientError: If the response data is invalid or cannot be parsed.

        """
        # Store a truncated copy of the response text for logging (just in case).
        raw_text_snippet = response.text[:500]

        try:
            data: Any = response.json()
            return CisaKevCatalog.model_validate(data)
        except ValidationError as e:
            self.logger.error(
                "Validation error while parsing KEV response",
                extra={"errors": e.errors(), "raw_response": raw_text_snippet},
            )
            raise ApiClientError("Invalid data received from the CISA KEV API") from e
        except ValueError as e:
            self.logger.error(
                "JSON decoding error",
                extra={"error": str(e), "raw_response": raw_text_snippet},
            )
            raise ApiClientError("Failed to decode JSON response") from e

    async def get_kev_json(self) -> CisaKevCatalog:
        """Retrieve the KEV catalog in JSON format.

        Returns:
            A `CisaKevCatalog` model containing the entire KEV dataset.

        Example:
            >>> async with CisaKevApiClient() as client:
            ...     kev_data = await client.get_kev_json()
            ...     print(kev_data.title, len(kev_data.vulnerabilities))

        """
        endpoint = "/feeds/known_exploited_vulnerabilities.json"
        self.logger.debug("Retrieving KEV JSON data", extra={"endpoint": endpoint})
        response: httpx.Response = await self._request("GET", endpoint, response_format="json")
        return await self._parse_response(response)

    async def get_kev_csv(self) -> bytes:
        """Retrieve the KEV catalog in CSV format.

        Returns:
            Raw CSV data as bytes.

        Example:
            >>> async with CisaKevApiClient() as client:
            ...     kev_csv = await client.get_kev_csv()
            ...     # Use `kev_csv` as needed, e.g., write to a file.

        """
        endpoint = "/csv/known_exploited_vulnerabilities.csv"
        self.logger.debug("Retrieving KEV CSV data", extra={"endpoint": endpoint})
        response: httpx.Response = await self._request("GET", endpoint, response_format="csv")
        return response.content

    async def get_kev_json_paginated(
        self,
        *,
        chunk_size: int = 1000,
    ) -> AsyncIterator[CisaKevCatalog]:
        """Asynchronously paginate through the KEV JSON data.

        Loads the entire KEV catalog once, then yields subsets of vulnerabilities
        in `CisaKevCatalog` models of size `chunk_size`.

        Args:
            chunk_size: Number of vulnerabilities per chunk.

        Yields:
            A `CisaKevCatalog` instance representing a chunk of vulnerabilities.

        Example:
            >>> async with CisaKevApiClient() as client:
            ...     async for chunk in client.get_kev_json_paginated(chunk_size=500):
            ...         print(len(chunk.vulnerabilities))

        """
        kev_catalog: CisaKevCatalog = await self.get_kev_json()
        total_vulns: int = len(kev_catalog.vulnerabilities)
        self.logger.debug(
            "Paginating KEV JSON data",
            extra={"total_vulnerabilities": total_vulns, "chunk_size": chunk_size},
        )

        for start in range(0, total_vulns, chunk_size):
            end: int = start + chunk_size
            chunk: CisaKevCatalog = CisaKevCatalog(
                catalogVersion=kev_catalog.catalog_version,
                dateReleased=kev_catalog.date_released,
                vulnerabilities=kev_catalog.vulnerabilities[start:end],
                count=len(kev_catalog.vulnerabilities[start:end]),
            )
            self.logger.debug(
                "Yielding KEV JSON chunk",
                extra={"start": start, "end": min(end, total_vulns)},
            )
            yield chunk
