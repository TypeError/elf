"""Pydantic models for the CISA Known Exploited Vulnerabilities (KEV) catalog.

These models define the structure and validation rules for interacting with the
CISA KEV catalog data, adhering to the official KEV schema:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json

The KEV database is distributed under the Creative Commons 0 1.0 License (CC0).
You are free to use this data in any lawful manner. Please see:
https://www.cisa.gov/sites/default/files/licenses/kev/license.txt

Attribution:
    The data utilized here is sourced from the Cybersecurity and Infrastructure Security Agency (CISA).

Classes:
    - `CisaKevVulnerability`: Represents a single vulnerability entry in the KEV catalog.
    - `CisaKevCatalog`: Represents the entire KEV catalog, including metadata and vulnerabilities.

Typical Usage Example:
    >>> from elf.sources.cisa_kev.models import CisaKevCatalog
    >>> catalog = CisaKevCatalog.parse_obj(api_response)
    >>> print(catalog.catalog_version, catalog.count, len(catalog.vulnerabilities))
    >>> for vuln in catalog.vulnerabilities:
    ...     print(vuln.cve_id, vuln.short_description)
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, constr, model_validator

JsonValue = str | int | float | bool | None | dict[str, "JsonValue"] | list["JsonValue"] | datetime


class CisaKevVulnerability(BaseModel):
    """Represents a single vulnerability entry in the CISA KEV catalog.

    Attributes:
        cve_id (str): The CVE identifier (e.g., "CVE-2021-34527").
            Must match the pattern: `^CVE-[0-9]{4}-[0-9]{4,19}$`.
        vendor_project (str): The vendor or project associated with the affected product.
        product (str): The name of the affected product.
        vulnerability_name (str): A short, descriptive name for the vulnerability.
        date_added (date): The date the vulnerability was added to the KEV catalog (YYYY-MM-DD).
        short_description (str): A brief description of the vulnerability.
        required_action (str): The recommended or required remediation action.
        due_date (date): The deadline for taking action (YYYY-MM-DD).
        known_ransomware_campaign_use (str | None): Indicates if ransomware campaigns exploit this vulnerability.
            - `"Known"` if associated with ransomware campaigns.
            - `"Unknown"` otherwise.
        notes (str | None): Additional notes or context about the vulnerability.
        cwes (list[str] | None): Associated CWE identifiers (e.g., "CWE-79").

    """

    cve_id: Annotated[str, constr(pattern=r"^CVE-\d{4}-\d{4,19}$")] = Field(
        ...,
        alias="cveID",
        description="CVE ID (e.g., CVE-2021-34527), following the format `CVE-YYYY-#########`.",
    )
    vendor_project: str = Field(
        ...,
        alias="vendorProject",
        description="Vendor or project name related to the affected product.",
    )
    product: str = Field(..., description="Name of the affected product.")
    vulnerability_name: str = Field(
        ..., alias="vulnerabilityName", description="Short, descriptive name of the vulnerability."
    )
    date_added: date = Field(
        ...,
        alias="dateAdded",
        description="Date the vulnerability was added to the KEV catalog (YYYY-MM-DD).",
    )
    short_description: str = Field(
        ..., alias="shortDescription", description="Brief description of the vulnerability."
    )
    required_action: str = Field(
        ..., alias="requiredAction", description="Recommended or required remediation action."
    )
    due_date: date = Field(
        ..., alias="dueDate", description="Deadline for addressing the vulnerability (YYYY-MM-DD)."
    )
    known_ransomware_campaign_use: str | None = Field(
        None,
        alias="knownRansomwareCampaignUse",
        description=(
            "Indicates ransomware exploitation: 'Known' for known campaigns, 'Unknown' otherwise."
        ),
    )
    notes: str | None = Field(
        None, description="Additional notes or context about the vulnerability."
    )
    cwes: list[str] | None = Field(
        None, description="List of CWE identifiers (e.g., ['CWE-79', 'CWE-89'])."
    )

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class CisaKevCatalog(BaseModel):
    """Represents the entire CISA Known Exploited Vulnerabilities (KEV) catalog.

    Attributes:
        catalog_version (str): Version number of the KEV catalog.
        date_released (datetime): Release date/time of the catalog in ISO 8601 format (UTC).
        count (int): Total number of vulnerabilities listed in the catalog.
        vulnerabilities (list[CisaKevVulnerability]): List of vulnerabilities in the KEV catalog.

    Example:
        >>> from elf.sources.cisa_kev.models import CisaKevCatalog
        >>> catalog = CisaKevCatalog.parse_obj(api_response)
        >>> print(catalog.catalog_version, catalog.count, len(catalog.vulnerabilities))

    """

    catalog_version: str = Field(
        ..., alias="catalogVersion", description="Version number of the KEV catalog."
    )
    date_released: datetime = Field(
        ...,
        alias="dateReleased",
        description="Release timestamp of the catalog (ISO 8601, e.g., 2024-01-15T12:00:00.000Z).",
    )
    count: int = Field(..., description="Total number of vulnerabilities in the KEV catalog.")
    vulnerabilities: list[CisaKevVulnerability] = Field(
        ..., description="List of vulnerabilities included in the KEV catalog."
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_date(cls, values: dict[str, JsonValue]) -> dict[str, JsonValue]:
        """Normalize the `dateReleased` field into a Python datetime object.

        Args:
            values (dict[str, JsonValue]): Dictionary of field values from the input data.

        Returns:
            dict[str, JsonValue]: Updated dictionary with `dateReleased` parsed as a datetime object.

        Raises:
            ValueError: If `dateReleased` is not in the correct format.

        """
        date_val = values.get("dateReleased")
        if isinstance(date_val, str):
            new_val = date_val.replace("Z", "+00:00")
            try:
                values["dateReleased"] = datetime.fromisoformat(new_val)
            except ValueError as err:
                raise ValueError(f"Invalid date-time format for dateReleased: {date_val}") from err
        return values

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=True,
    )
