"""Sources module for the `elf` package.

This module provides API clients and models for interacting with data sources such as:
    - CISA KEV
    - FIRST EPSS
    - NIST NVD

Public API:
    - API Clients:
        - `CisaKevApiClient`
        - `FirstEpssApiClient`
        - `NistNvdApiClient`
    - Models:
        - CISA KEV Models:
            - `CisaKevCatalog`
            - `CisaKevVulnerability`
        - FIRST EPSS Models:
            - `FirstEpssScoreResponse`
            - `EpssScoreItem`
        - NIST NVD Models:
            - `NistNvdCveResponse`
            - `NistNvdCveHistoryResponse`
            - `CveItem`
            - `Change`
            - `ChangeDetail`
"""

from .cisa_kev.client import CisaKevApiClient
from .cisa_kev.models import CisaKevCatalog, CisaKevVulnerability
from .first_epss.client import FirstEpssApiClient
from .first_epss.models import EpssScoreItem, FirstEpssScoreResponse
from .nist_nvd.client import NistNvdApiClient
from .nist_nvd.models import (
    Change,
    ChangeDetail,
    CveItem,
    NistNvdCveHistoryResponse,
    NistNvdCveResponse,
)

__all__ = [
    # Clients
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
