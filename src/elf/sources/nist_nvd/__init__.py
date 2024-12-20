"""NIST NVD API module.

This module provides:
    - The `NistNvdApiClient` for interacting with the NIST National Vulnerability Database API.
    - Pydantic models for handling NVD responses and data structures.
"""

from .client import NistNvdApiClient
from .models import (
    Change,
    ChangeDetail,
    CveItem,
    NistNvdCveHistoryResponse,
    NistNvdCveResponse,
)

__all__ = [
    "NistNvdApiClient",
    "NistNvdCveResponse",
    "NistNvdCveHistoryResponse",
    "CveItem",
    "Change",
    "ChangeDetail",
]
