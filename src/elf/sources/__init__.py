"""Sources module for the `elf` package.

Provides API clients and data models for interacting with:
    - CISA Known Exploited Vulnerabilities (KEV)
    - FIRST Exploit Prediction Scoring System (EPSS)
    - NIST National Vulnerability Database (NVD)

Exports:
    - API Clients:
        - `CisaKevApiClient`
        - `FirstEpssApiClient`
        - `NistNvdApiClient`
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
"""

from .cisa_kev.client import CisaKevApiClient
from .cisa_kev.models import CisaKevCatalog, CisaKevVulnerability
from .first_epss.client import FirstEpssApiClient
from .first_epss.models import FirstEpssEpssScoreItem, FirstEpssOrderOption, FirstEpssScoreResponse
from .nist_nvd.client import NistNvdApiClient
from .nist_nvd.models import (
    NistNvdChange,
    NistNvdChangeDetail,
    NistNvdCveHistoryResponse,
    NistNvdCveItem,
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
    "FirstEpssEpssScoreItem",
    "FirstEpssOrderOption",
    # NIST NVD Models
    "NistNvdCveResponse",
    "NistNvdCveHistoryResponse",
    "NistNvdCveItem",
    "NistNvdChange",
    "NistNvdChangeDetail",
]
