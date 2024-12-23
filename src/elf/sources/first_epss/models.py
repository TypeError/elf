"""Data models for representing EPSS (Exploit Prediction Scoring System) API responses and scores.

These Pydantic models structure and validate data returned by the EPSS API:
https://www.first.org/epss/api

EPSS provides probability-based exploit predictions for CVEs, helping security teams
assess and prioritize vulnerabilities effectively.

Classes:
    - FirstEpssTimeSeriesEntry: Represents a time-series entry for a CVE's EPSS score.
    - FirstEpssEpssScoreItem: Represents a single CVE score entry, including EPSS score and percentile.
    - FirstEpssScoreResponse: Encapsulates an API response containing multiple CVE scores.
    - FirstEpssOrderOption: Enumeration for sorting options in the EPSS API.
    - FirstEpssAccessLevel: Enumeration for API response access levels.
    - FirstEpssResponseStatus: Enumeration for API response statuses.

Attributes:
    CVE_PATTERN (re.Pattern): Regex pattern to validate CVE identifiers.

Usage Agreement:
    EPSS is developed by a community of researchers and practitioners.
    Use of EPSS scores is granted freely. Please cite EPSS appropriately:
    Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., & Adjerid, I. (2021).
    Exploit Prediction Scoring System, Digital Threats Research and Practice, 2(3).
    (https://www.first.org/epss)

Typical usage:
    >>> from elf.sources.first_epss.models import FirstEpssScoreResponse
    >>> response = FirstEpssScoreResponse.parse_obj(api_response)
    >>> high_scores = response.filter_data(threshold=0.5, key="epss")
    >>> sorted_scores = response.sorted_data(keys=["percentile"], reverse=False)

"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class FirstEpssOrderOption(str, Enum):
    """Enumeration for sorting options in the EPSS API response."""

    EPSS_ASC = "epss"
    EPSS_DESC = "!epss"
    PERCENTILE_ASC = "percentile"
    PERCENTILE_DESC = "!percentile"


class FirstEpssAccessLevel(str, Enum):
    """Enumeration for API response access levels."""

    PUBLIC = "public"
    PRIVATE = "private, no-cache"


class FirstEpssResponseStatus(str, Enum):
    """Enumeration for API response statuses."""

    OK = "OK"
    ERROR = "ERROR"


class FirstEpssTimeSeriesEntry(BaseModel):
    """Represents a time-series entry for a CVE's EPSS score.

    Attributes:
        epss (float): Probability of exploitation (0.0 to 1.0).
        percentile (float): Percentile rank (0.0 to 100.0).
        date (datetime): Timestamp for the EPSS score entry.

    """

    epss: Annotated[float, Field(ge=0.0, le=1.0, description="EPSS score (0.0 to 1.0).")]
    percentile: Annotated[
        float, Field(ge=0.0, le=100.0, description="Percentile rank (0.0 to 100.0).")
    ]
    date: datetime = Field(..., description="Date of the EPSS score entry.")

    @field_validator("date", mode="before")
    @classmethod
    def parse_date(cls, value: str | datetime) -> datetime:
        """Ensure the date is a valid datetime object."""
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("Invalid date format, expected ISO 8601 string") from None


class FirstEpssEpssScoreItem(BaseModel):
    """Represents a single CVE entry with its EPSS score.

    Attributes:
        cve (str): CVE identifier (e.g., "CVE-2023-12345").
        epss (float): Probability of exploitation (0.0 to 1.0).
        percentile (float): Percentile rank (0.0 to 100.0).
        date (datetime): Timestamp when the EPSS score was calculated.
        time_series (list[FirstEpssTimeSeriesEntry] | None): Historical EPSS scores (if requested).

    """

    cve: str = Field(..., description="CVE identifier, e.g., 'CVE-2021-34527'.")
    epss: Annotated[float, Field(ge=0.0, le=1.0, description="EPSS score (0.0 to 1.0).")]
    percentile: Annotated[
        float, Field(ge=0.0, le=100.0, description="Percentile rank (0.0 to 100.0).")
    ]
    date: datetime = Field(
        ..., description="UTC timestamp indicating when the EPSS score was calculated."
    )
    time_series: list[FirstEpssTimeSeriesEntry] | None = Field(
        None, description="Time-series data for the CVE if requested.", alias="time-series"
    )

    @field_validator("cve", mode="after")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        """Ensure CVE format conforms to CVE-YYYY-NNNN pattern."""
        if not CVE_PATTERN.match(v):
            raise ValueError("CVE ID must follow the format 'CVE-YYYY-NNNN'")
        return v.upper()


class FirstEpssScoreResponse(BaseModel):
    """Represents the response from the EPSS API containing multiple CVE scores.

    Attributes:
        status (FirstEpssResponseStatus): Status of the response.
        status_code (int): HTTP status code.
        version (str): EPSS API version.
        access (FirstEpssAccessLevel): Access level of the response.
        total (int): Total number of records available.
        offset (int): Starting record offset.
        limit (int): Number of records returned.
        data (list[FirstEpssEpssScoreItem]): List of CVE EPSS scores.

    """

    status: FirstEpssResponseStatus = Field(..., description="Status of the EPSS API response.")
    status_code: int = Field(..., alias="status-code", description="HTTP status code.")
    version: str = Field(..., description="Version of the EPSS API.")
    access: FirstEpssAccessLevel = Field(..., description="Access level of the API response.")
    total: int = Field(..., description="Total number of records available.")
    offset: int = Field(..., description="Starting offset for records.")
    limit: int = Field(..., description="Maximum number of records returned.")
    data: list[FirstEpssEpssScoreItem] = Field(..., description="List of CVE EPSS scores.")

    def filter_data(
        self, threshold: float, key: Literal["epss", "percentile"] = "epss"
    ) -> list[FirstEpssEpssScoreItem]:
        """Filter CVE entries based on a threshold."""
        if key not in {"epss", "percentile"}:
            raise ValueError(f"Unsupported filter key: {key}")
        return [item for item in self.data if getattr(item, key) > threshold]

    def sorted_data(
        self,
        keys: list[Literal["epss", "percentile"]] | None = None,
        reverse: bool = True,
    ) -> list[FirstEpssEpssScoreItem]:
        """Sort CVE entries by specified attributes."""
        if keys is None:
            keys = ["epss"]

        if not all(key in {"epss", "percentile"} for key in keys):
            raise ValueError(f"Unsupported sort keys: {keys}")

        return sorted(
            self.data,
            key=lambda x: tuple(getattr(x, key) for key in keys),
            reverse=reverse,
        )
