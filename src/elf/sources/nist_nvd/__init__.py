"""NIST NVD API module.

Provides tools for interacting with the NIST National Vulnerability Database (NVD) API.

Features:
    - `NistNvdApiClient`: API client for fetching and processing NVD CVE data.
    - Data models for validating CVE responses and change histories.

Exports:
    - API Client:
        - `NistNvdApiClient`
    - Models:
        - `NistNvdCveResponse`: Represents NVD CVE responses.
        - `NistNvdCveHistoryResponse`: Represents NVD CVE change history.
        - `NistNvdCveItem`: Represents individual CVE items.
        - `NistNvdChange`: Represents CVE change events.
        - `NistNvdChangeDetail`: Represents detailed information about CVE changes.

Example Usage:
    >>> from elf.sources.nist_nvd import NistNvdApiClient
    >>> async with NistNvdApiClient() as client:
    >>>     cve = await client.get_cve("CVE-2023-12345")
    >>>     print(cve.id, cve.metrics)
"""

from .client import NistNvdApiClient
from .models import (
    NistNvdChange,
    NistNvdChangeDetail,
    NistNvdCveHistoryResponse,
    NistNvdCveItem,
    NistNvdCveResponse,
)

__all__ = [
    "NistNvdApiClient",
    "NistNvdCveResponse",
    "NistNvdCveHistoryResponse",
    "NistNvdCveItem",
    "NistNvdChange",
    "NistNvdChangeDetail",
]
