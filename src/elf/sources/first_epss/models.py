"""Data models for representing EPSS (Exploit Prediction Scoring System) API responses and scores.

These Pydantic models structure and validate data returned by the EPSS API:
https://www.first.org/epss/api

EPSS provides probability-based exploit predictions for CVEs, helping security teams
assess risk and prioritize vulnerabilities more efficiently.

Classes:
    - TimeSeriesEntry: Represents a single time-series entry for a CVE's EPSS score over time.
    - EpssScoreItem: Represents a single CVE score entry, including its EPSS score and percentile.
    - FirstEpssScoreResponse: Encapsulates an API response containing multiple `EpssScoreItem` records.

Attributes:
    CVE format: Must match the pattern "CVE-YYYY-NNNN" (with possible extended numbering).
    EPSS score: Probability of exploitation [0.0, 1.0].
    Percentile: Percentile rank [0.0, 100.0], indicating how the CVE's score compares to others.

Usage Agreement:
    EPSS is developed by a community of researchers and practitioners.
    Use of EPSS scores is granted freely. Please cite EPSS appropriately:
    Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., & Adjerid, I. (2021).
    Exploit Prediction Scoring System, Digital Threats Research and Practice, 2(3).
    (https://www.first.org/epss)

Typical usage example:
    >>> from elf.sources.first_epss.models import FirstEpssScoreResponse
    >>> response = FirstEpssScoreResponse.parse_obj(api_response)
    >>> high_epss = response.filter_data(threshold=0.5, key="epss")
    >>> sorted_by_percentile = response.sorted_data(keys=["percentile"], reverse=False)

"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator


class AccessLevel(str, Enum):
    """Enumeration for access levels in the EPSS API response."""

    PUBLIC = "public"
    PRIVATE = "private, no-cache"


class ResponseStatus(str, Enum):
    """Enumeration for response statuses in the EPSS API response."""

    OK = "OK"
    ERROR = "ERROR"


class TimeSeriesEntry(BaseModel):
    """Model for a single time-series entry in EPSS data."""

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


class EpssScoreItem(BaseModel):
    """Represents a single EPSS score entry for a specific CVE.

    The EPSS score approximates the probability that a CVE will be exploited
    in the wild within the next 30 days.

    Attributes:
        cve (str): The CVE identifier, must match the pattern: "CVE-YYYY-NNNN" (with possible additional digits).
        epss (float): The EPSS score, a probability in the range [0.0, 1.0].
        percentile (float): The percentile rank of this CVE's EPSS score in the range [0.0, 100.0].
        date (datetime): The UTC timestamp when this EPSS score was calculated.
        time_series (Optional[list[TimeSeriesEntry]]): Time-series data if `scope="time-series"` is used.

    Example:
        >>> item = EpssScoreItem(
        ...     cve="CVE-2021-34527",
        ...     epss=0.42,
        ...     percentile=75.0,
        ...     date=datetime.strptime("2023-09-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
        ... )
        >>> print(item.cve, item.epss, item.percentile, item.date)

    """

    cve: str = Field(..., description="CVE identifier, e.g., 'CVE-2021-34527'.")
    epss: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="EPSS score (0.0 to 1.0), representing exploitation probability.",
    )
    percentile: float = Field(
        ..., ge=0.0, le=100.0, description="Percentile rank of the EPSS score (0.0 to 100.0)."
    )
    date: datetime = Field(
        ..., description="UTC timestamp indicating when the EPSS score was calculated."
    )
    time_series: list[TimeSeriesEntry] | None = Field(
        None, description="Time-series data for the CVE if requested.", alias="time-series"
    )

    @field_validator("cve", mode="after")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        """Ensure CVE format conforms to CVE-YYYY-NNNN pattern.

        Raises:
            ValueError: If the CVE ID does not match required pattern.

        """
        import re

        if not re.match(r"^CVE-\d{4}-\d{4,}$", v, re.IGNORECASE):
            raise ValueError("CVE ID must follow the format 'CVE-YYYY-NNNN'")
        return v.upper()


class FirstEpssScoreResponse(BaseModel):
    """Represents a response from the FIRST.org EPSS API containing multiple CVE EPSS scores.

    The response typically includes metadata such as status, version, and pagination fields,
    along with a `data` array of `EpssScoreItem` entries.

    Attributes:
        status (Literal["OK", "ERROR"]): Response status.
        status_code (int): HTTP status code of the response.
        version (str): Version of the EPSS API used.
        access (Literal["public", "private, no-cache"]): Cache access directive.
        total (int): Total number of records available.
        offset (int): Starting record offset for the current response.
        limit (int): Maximum number of records returned in this batch.
        data (list[EpssScoreItem]): List of EPSS score items for various CVEs.

    Methods:
        filter_data(threshold: float, key: Literal["epss", "percentile"]) -> list[EpssScoreItem]:
            Filter the EPSS data by a minimum threshold on the specified attribute ("epss" or "percentile").

        sorted_data(keys: list[Literal["epss", "percentile"]] | None, reverse: bool) -> list[EpssScoreItem]:
            Sort the data by given attributes (e.g., "epss" or "percentile"). Defaults to sorting by "epss" descending.

    Example:
        >>> response = FirstEpssScoreResponse.parse_obj(api_response)
        >>> filtered = response.filter_data(threshold=0.5, key="epss")
        >>> sorted_items = response.sorted_data(keys=["percentile"], reverse=False)

    """

    status: ResponseStatus = Field(..., description="Status of the EPSS API response.")
    status_code: int = Field(..., alias="status-code", description="HTTP status code.")
    version: str = Field(..., description="Version of the EPSS API.")
    access: AccessLevel = Field(..., description="Access level of the API response.")
    total: int = Field(..., description="Total number of records available.")
    offset: int = Field(..., description="Starting offset for records.")
    limit: int = Field(..., description="Maximum number of records returned.")
    data: list[EpssScoreItem] = Field(..., description="List of CVE EPSS scores.")

    def filter_data(
        self, threshold: float, key: Literal["epss", "percentile"] = "epss"
    ) -> list[EpssScoreItem]:
        """Filter `data` items by a specified attribute threshold.

        Args:
            threshold (float): Minimum value for the attribute filter.
            key (Literal["epss", "percentile"], optional): Attribute to filter by, either "epss" or "percentile". Defaults to "epss".

        Returns:
            list[EpssScoreItem]: A list of EpssScoreItem objects exceeding the threshold.

        Raises:
            ValueError: If an unsupported key is provided.

        """
        if key not in {"epss", "percentile"}:
            raise ValueError(f"Unsupported filter key: {key}")
        return [item for item in self.data if getattr(item, key) > threshold]

    def sorted_data(
        self,
        keys: list[Literal["epss", "percentile"]] | None = None,
        reverse: bool = True,
    ) -> list[EpssScoreItem]:
        """Sort the EPSS `data` list by one or more attributes.

        Args:
            keys (Optional[list[Literal["epss", "percentile"]]], optional): Attributes to sort by (e.g., ["epss", "percentile"]). Defaults to ["epss"] if not provided.
            reverse (bool, optional): Whether to sort in descending order. Defaults to True.

        Returns:
            list[EpssScoreItem]: A list of EpssScoreItem objects sorted by the specified attributes.

        Raises:
            ValueError: If unsupported keys are provided.

        """
        if keys is None:
            keys = ["epss"]

        if not all(key in {"epss", "percentile"} for key in keys):
            raise ValueError(f"Unsupported sort keys: {keys}")

        return sorted(
            self.data,
            key=lambda x: tuple(getattr(x, key) for key in keys),
            reverse=reverse,
        )
