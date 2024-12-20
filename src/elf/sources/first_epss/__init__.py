"""FIRST EPSS API module.

This module provides:
    - The `FirstEpssApiClient` for interacting with the FIRST EPSS API.
    - Pydantic models for handling EPSS responses and data structures.
"""

from .client import FirstEpssApiClient
from .models import (
    EpssScoreItem,
    FirstEpssScoreResponse,
)

__all__ = [
    "FirstEpssApiClient",
    "FirstEpssScoreResponse",
    "EpssScoreItem",
]
