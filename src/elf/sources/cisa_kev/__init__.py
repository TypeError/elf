"""CISA KEV API module.

Provides tools for interacting with the CISA Known Exploited Vulnerabilities API.

Features:
    - `CisaKevApiClient`: API client for fetching data from the KEV catalog.
    - Data models for validating and interacting with KEV responses.

Exports:
    - API Client:
        - `CisaKevApiClient`
    - Models:
        - `CisaKevCatalog`: Represents the entire KEV catalog.
        - `CisaKevVulnerability`: Represents individual vulnerability entries.

Example Usage:
    >>> from elf.sources.cisa_kev import CisaKevApiClient
    >>> async with CisaKevApiClient() as client:
    >>>     catalog = await client.get_kev_json()
    >>>     print(catalog.catalog_version)
"""

from .client import CisaKevApiClient
from .models import CisaKevCatalog, CisaKevVulnerability

__all__ = [
    "CisaKevApiClient",
    "CisaKevCatalog",
    "CisaKevVulnerability",
]
