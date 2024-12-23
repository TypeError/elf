"""The `elf` package provides tools and API clients for interacting with vulnerability management data.

This package enables seamless integration with data sources such as:
    - NIST NVD (National Vulnerability Database)
    - CISA KEV (Known Exploited Vulnerabilities)
    - FIRST EPSS (Exploit Prediction Scoring System)

Public API:
    - API Clients:
        - `CisaKevApiClient`
        - `FirstEpssApiClient`
        - `NistNvdApiClient`
    - Core Components:
        - `BaseApiClient`: Base class for API clients.
        - Custom exceptions for error handling.
    - Models:
        - CISA KEV:
            - `CisaKevCatalog`
            - `CisaKevVulnerability`
        - FIRST EPSS:
            - `FirstEpssScoreResponse`
            - `FirstEpssEpssScoreItem`
            - `FirstEpssOrderOption`
        - NIST NVD:
            - `NistNvdCveResponse`
            - `NistNvdCveHistoryResponse`
            - `NistNvdCveItem`
            - `NistNvdChange`
            - `NistNvdChangeDetail`

Example Usage:
    >>> from elf import CisaKevApiClient, FirstEpssApiClient, NistNvdApiClient, FirstEpssOrderOption
    >>> async with CisaKevApiClient() as kev_client:
    >>>     kev_data = await kev_client.get_kev_json()
    >>> async with FirstEpssApiClient() as epss_client:
    >>>     epss_data = await epss_client.get_scores_json(["CVE-2022-12345"], order=FirstEpssOrderOption.EPSS_DESC)
    >>> async with NistNvdApiClient() as nvd_client:
    >>>     cve_data = await nvd_client.get_cve("CVE-2023-12345")
"""

from .core import (
    ApiClientDataError,
    ApiClientError,
    ApiClientHTTPError,
    ApiClientNetworkError,
    ApiClientTimeoutError,
    BaseApiClient,
)
from .sources import (
    CisaKevApiClient,
    CisaKevCatalog,
    CisaKevVulnerability,
    FirstEpssApiClient,
    FirstEpssEpssScoreItem,
    FirstEpssOrderOption,
    FirstEpssScoreResponse,
    NistNvdApiClient,
    NistNvdChange,
    NistNvdChangeDetail,
    NistNvdCveHistoryResponse,
    NistNvdCveItem,
    NistNvdCveResponse,
)

__all__ = [
    # Core Components
    "BaseApiClient",
    "ApiClientError",
    "ApiClientHTTPError",
    "ApiClientTimeoutError",
    "ApiClientNetworkError",
    "ApiClientDataError",
    # API Clients
    "CisaKevApiClient",
    "FirstEpssApiClient",
    "NistNvdApiClient",
    # CISA KEV Models
    "CisaKevCatalog",
    "CisaKevVulnerability",
    # FIRST EPSS Models
    "FirstEpssScoreResponse",
    "FirstEpssEpssScoreItem",
    "FirstEpssOrderOption",
    # NIST NVD Models
    "NistNvdCveResponse",
    "NistNvdCveHistoryResponse",
    "NistNvdCveItem",
    "NistNvdChange",
    "NistNvdChangeDetail",
]
