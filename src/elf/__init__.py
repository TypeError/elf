"""The `elf` package provides tools and API clients for interacting with vulnerability management data.

This package enables seamless integration with data sources such as NIST NVD, CISA KEV, and FIRST EPSS.

Modules:
    - `core`: Core components including the base API client and custom exceptions.
    - `sources`: API clients and models for CISA KEV, FIRST EPSS, and NIST NVD.

Public API:
    - API Clients:
        - `CisaKevApiClient`: Interact with the CISA Known Exploited Vulnerabilities (KEV) API.
        - `FirstEpssApiClient`: Interact with the FIRST EPSS API.
        - `NistNvdApiClient`: Interact with the NIST National Vulnerability Database (NVD) API.

    - Core Components:
        - `BaseApiClient`: Base class for creating API clients.
        - Custom exceptions for robust error handling.

    - Models:
        - CISA KEV:
            - `CisaKevCatalog`: Representation of the KEV catalog.
            - `CisaKevVulnerability`: Individual vulnerability in the KEV catalog.
        - FIRST EPSS:
            - `FirstEpssScoreResponse`: EPSS response structure.
            - `EpssScoreItem`: Individual EPSS score item.
        - NIST NVD:
            - `NistNvdCveResponse`: CVE response from NVD.
            - `NistNvdCveHistoryResponse`: CVE change history response from NVD.
            - `CveItem`: Individual CVE item in the NVD response.
            - `Change`: CVE change item.
            - `ChangeDetail`: Details of a specific CVE change.

Example Usage:
    >>> from elf import CisaKevApiClient, FirstEpssApiClient, NistNvdApiClient
    >>> async with CisaKevApiClient() as kev_client:
    >>>     kev_data = await kev_client.get_kev_json()
    >>> async with FirstEpssApiClient() as epss_client:
    >>>     epss_data = await epss_client.get_scores_json(["CVE-2022-12345"])
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
    Change,
    ChangeDetail,
    CisaKevApiClient,
    CisaKevCatalog,
    CisaKevVulnerability,
    CveItem,
    EpssScoreItem,
    FirstEpssApiClient,
    FirstEpssScoreResponse,
    NistNvdApiClient,
    NistNvdCveHistoryResponse,
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
    "EpssScoreItem",
    # NIST NVD Models
    "NistNvdCveResponse",
    "NistNvdCveHistoryResponse",
    "CveItem",
    "Change",
    "ChangeDetail",
]
