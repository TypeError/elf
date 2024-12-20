"""Data models for representing EPSS (Exploit Prediction Scoring System) API responses and scores.

These Pydantic models structure and validate data returned by the EPSS API:
https://www.first.org/epss/api

EPSS provides probability-based exploit predictions for CVEs, helping security teams
assess risk and prioritize vulnerabilities more efficiently.

Classes:
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
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EpssScoreItem(BaseModel):
    """Represents a single EPSS score entry for a specific CVE.

    The EPSS score approximates the probability that a CVE will be exploited
    in the wild within the next 30 days.

    Attributes:
        cve (str): The CVE identifier, must match the pattern: "CVE-YYYY-NNNN" (with possible additional digits).
        epss (float): The EPSS score, a probability in the range [0.0, 1.0].
        percentile (float): The percentile rank of this CVE's EPSS score in the range [0.0, 100.0].
        date (datetime): The UTC timestamp when this EPSS score was calculated.

    Example:
        >>> item = EpssScoreItem(
        ...     cve="CVE-2021-34527",
        ...     epss=0.42,
        ...     percentile=75.0,
        ...     date="2023-09-01T00:00:00Z"
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

    @field_validator("cve", mode="after")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        """Ensure CVE format conforms to CVE-YYYY-NNNN pattern.

        Raises:
            ValueError: If the CVE ID does not match required pattern.

        """
        import re

        if not re.match(r"^CVE-\d{4}-\d{4,}$", v):
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
            Sort the data by given attributes (e.g. "epss" or "percentile"). Defaults to sorting by "epss" descending.

    Example:
        >>> response = FirstEpssScoreResponse.parse_obj(api_response)
        >>> filtered = response.filter_data(threshold=0.5, key="epss")
        >>> sorted_items = response.sorted_data(keys=["percentile"], reverse=False)

    """

    status: Literal["OK", "ERROR"] = Field(
        ..., description="Status of the EPSS API response (OK or ERROR)."
    )
    status_code: int = Field(
        ..., alias="status-code", description="HTTP status code of the response."
    )
    version: str = Field(..., description="Version of the EPSS API.")
    access: Literal["public", "private, no-cache"] = Field(
        ..., description="Cache directive for the response data."
    )
    total: int = Field(..., description="Total number of available EPSS records.")
    offset: int = Field(..., description="Starting index of returned records.")
    limit: int = Field(..., description="Maximum number of records returned in this response.")
    data: list[EpssScoreItem] = Field(..., description="List of EPSS scores for various CVEs.")

    def filter_data(
        self, threshold: float, key: Literal["epss", "percentile"] = "epss"
    ) -> list[EpssScoreItem]:
        """Filter `data` items by a specified attribute threshold.

        Args:
            threshold: Minimum value for the attribute filter.
            key: Attribute to filter by, either "epss" or "percentile". Defaults to "epss".

        Returns:
            A list of EpssScoreItem objects exceeding the threshold.

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
            keys: Attributes to sort by (e.g., ["epss", "percentile"]). Defaults to ["epss"] if not provided.
            reverse: Whether to sort in descending order. Defaults to True.

        Returns:
            A list of EpssScoreItem objects sorted by the specified attributes.

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
