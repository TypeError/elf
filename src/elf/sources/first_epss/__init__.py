"""FIRST EPSS API module.

Provides tools for interacting with the FIRST Exploit Prediction Scoring System (EPSS) API.

Features:
    - `FirstEpssApiClient`: API client for retrieving and filtering EPSS scores.
    - Data models for validating EPSS responses.
    - Enumeration for sorting options.

Exports:
    - API Client:
        - `FirstEpssApiClient`
    - Models:
        - `FirstEpssScoreResponse`: Encapsulates EPSS response data.
        - `FirstEpssEpssScoreItem`: Represents individual EPSS score entries.
        - `FirstEpssOrderOption`: Enumeration for sorting options.

Example Usage:
    >>> from elf.sources.first_epss import FirstEpssApiClient, FirstEpssOrderOption
    >>> async with FirstEpssApiClient() as client:
    >>>     scores = await client.get_scores_json(["CVE-2022-12345"], order=FirstEpssOrderOption.EPSS_DESC)
    >>>     print(scores.data)
"""

from .client import FirstEpssApiClient
from .models import FirstEpssEpssScoreItem, FirstEpssOrderOption, FirstEpssScoreResponse

__all__ = [
    "FirstEpssApiClient",
    "FirstEpssOrderOption",
    "FirstEpssScoreResponse",
    "FirstEpssEpssScoreItem",
]
