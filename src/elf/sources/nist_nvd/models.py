"""Models for processing and interacting with NVD (National Vulnerability Database) data.

These Pydantic models represent data structures returned by the NVD Vulnerability and Change History APIs,
ensuring data validation and conformance to the NIST schemas and specifications.

By leveraging these models, you can:
    - Parse and validate responses from NVD APIs (Vulnerability and History).
    - Access and process CVE details such as descriptions, references, metrics, configurations, weaknesses, tags, and vendor comments.
    - Understand and handle CVSS scoring information (v2, v3.1), as well as historical changes in CVEs.

All fields and classes are annotated with docstrings reflecting the NVD API documentation:
https://nvd.nist.gov/developers/vulnerabilities

Example:
    >>> from elf.sources.nist_nvd.models import NistNvdCveResponse
    >>> response = NistNvdCveResponse.parse_obj(api_response)
    >>> for vuln_item in response.vulnerabilities:
    ...     cve = vuln_item.cve
    ...     print(cve.id, cve.metrics)

Note:
    - Required fields are always returned by the NVD API (may be empty strings in some cases).
    - Optional fields are returned only if data is present.
    - CVSS metrics may vary depending on when the CVE was published and if it has been reanalyzed.

"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, constr, model_validator

# Enumerations for severity and tags according to NVD documentation.
SeverityType = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TagEnum = Literal["unsupported-when-assigned", "exclusively-hosted-service", "disputed"]
ScoreType = float


class NistNvdLangString(BaseModel):
    """Represents a localized description string.

    Attributes:
        lang (str): Two-letter language code (ISO 639-1), e.g., 'en' for English.
        value (str): The textual description, up to 4096 characters.

    """

    lang: Annotated[str, constr(min_length=2, max_length=2)] = Field(
        ...,
        description="Two-letter language code (ISO 639-1) representing the language of the description.",
    )
    value: Annotated[str, constr(max_length=4096)] = Field(
        ..., description="Localized description text, up to 4096 characters."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdReference(BaseModel):
    """Represents a reference link with optional source and tags.

    References provide supplemental information relevant to the vulnerability,
    possibly containing advisories, reports, media mentions, etc.

    Attributes:
        url (AnyUrl): URL to the external reference.
        source (Optional[str]): The organization that provided the reference information.
        tags (Optional[List[str]]): Categorized tags for the reference (e.g., 'vendor-advisory', 'third-party-advisory').

    """

    url: AnyUrl = Field(
        ..., description="Reference URL providing supplemental vulnerability information."
    )
    source: str | None = Field(
        None, description="Organization that provided the reference information."
    )
    tags: list[str] | None = Field(
        None, description="List of tags describing the type of reference."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdVendorComment(BaseModel):
    """An official vendor comment regarding a CVE.

    Vendor comments can provide remediation guidance, analysis, or additional
    clarity on the applicability and impact of the vulnerability.

    Attributes:
        organization (str): The name of the organization providing the comment.
        comment (str): The content of the vendor's comment.
        last_modified (datetime): The date and time when the comment was last updated.

    """

    organization: str = Field(
        ..., description="Name of the organization providing the vendor comment."
    )
    comment: str = Field(..., description="The actual text of the vendor comment.")
    last_modified: datetime = Field(
        alias="lastModified", description="Timestamp of last modification to the comment."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdWeakness(BaseModel):
    """Represents a known weakness (e.g., CWE) associated with the CVE.

    Attributes:
        source (str): Organization providing the weakness information.
        type (str): Type of the weakness (often a CWE identifier).
        description (List[LangString]): Localized descriptions of the weakness.

    """

    source: str = Field(..., description="Source organization of the weakness data.")
    type: str = Field(..., description="Type or identifier of the weakness, e.g., CWE-79.")
    description: list[NistNvdLangString] = Field(
        ..., description="Localized descriptions of the weakness."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCpeMatch(BaseModel):
    """CPE match criteria identifying affected products or configurations.

    Part of the configuration data, these criteria specify which products
    or product ranges are affected by the vulnerability.

    Attributes:
        vulnerable (bool): Indicates if the specified product criteria is vulnerable.
        criteria (str): The CPE string identifying a product or product family.
        match_criteria_id (str): A unique identifier (UUID) for the match criteria.
        version_start_excluding (Optional[str]): Start version excluded from the vulnerable range.
        version_start_including (Optional[str]): Start version included in the vulnerable range.
        version_end_excluding (Optional[str]): End version excluded from the vulnerable range.
        version_end_including (Optional[str]): End version included from the vulnerable range.

    """

    vulnerable: bool = Field(
        ..., description="True if the identified product/version is vulnerable."
    )
    criteria: str = Field(..., description="CPE string that identifies the affected product.")
    match_criteria_id: str = Field(
        alias="matchCriteriaId", description="UUID for the match criteria."
    )
    version_start_excluding: str | None = Field(
        alias="versionStartExcluding",
        default=None,
        description="Starting version that is excluded from the vulnerable range.",
    )
    version_start_including: str | None = Field(
        alias="versionStartIncluding",
        default=None,
        description="Starting version that is included in the vulnerable range.",
    )
    version_end_excluding: str | None = Field(
        alias="versionEndExcluding",
        default=None,
        description="Ending version that is excluded from the vulnerable range.",
    )
    version_end_including: str | None = Field(
        alias="versionEndIncluding",
        default=None,
        description="Ending version that is included in the vulnerable range.",
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdNode(BaseModel):
    """Defines a logical configuration node that may contain CPE matches or child nodes.

    The `operator` indicates how the conditions within the node relate
    (AND/OR). The `negate` flag can invert the logic of the node.
    Nodes will contain either `cpe_match` entries or `children` nodes,
    forming a logical tree.

    Attributes:
        operator (Literal["AND", "OR"]): Logical operator for the node's children or matches.
        negate (bool): If True, negates the logic of the operator applied to this node.
        cpe_match (Optional[List[CpeMatch]]): List of product/version match criteria at this node.
        children (Optional[List[Node]]): Child nodes for more complex logical structures.

    """

    operator: Literal["AND", "OR"] = Field(
        ..., description="Logical operator for combining child conditions."
    )
    negate: bool = Field(..., description="Indicates whether the node's logic is negated.")
    cpe_match: list[NistNvdCpeMatch] | None = Field(
        alias="cpeMatch", default=None, description="CPE matches defining affected products."
    )
    children: list[NistNvdNode] | None = Field(
        default=None, description="Child nodes to form complex logical structures."
    )

    @model_validator(mode="after")
    def check_cpe_match_or_children(self) -> NistNvdNode:
        """Ensure that either cpe_match or children is present."""
        if not self.cpe_match and not self.children:
            raise ValueError("Either cpe_match or children must be present in a Node.")
        return self

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdConfiguration(BaseModel):
    """Represents a set of configuration nodes conveying product applicability.

    This object identifies which products, versions, or configurations are
    affected by the CVE, using CPE match criteria and logical operators.

    Attributes:
        nodes (List[Node]): One or more logical nodes detailing product applicability conditions.

    """

    nodes: list[NistNvdNode] = Field(
        ..., description="List of logical nodes describing configurations."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCveTag(BaseModel):
    """CVE Tags providing contextual classification or notes about the CVE.

    These tags can indicate special conditions like disputed vulnerabilities,
    exclusively hosted services, or unsupported conditions.

    Attributes:
        source_identifier (Optional[str]): Identifier (email or UUID) of the source that contributed the tag info.
        tags (List[TagEnum]): List of tags (e.g., 'disputed', 'exclusively-hosted-service').

    """

    source_identifier: str | None = Field(
        alias="sourceIdentifier",
        default=None,
        description="Email address or UUID of the source contributing the tag.",
    )
    tags: list[TagEnum] = Field(
        ..., description="List of tags providing contextual details about the CVE."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCvssV31Data(BaseModel):
    """CVSS v3.1 metric data describing the severity and exploitation characteristics of a vulnerability.

    Attributes:
        version (Literal["3.1"]): CVSS version number.
        vector_string (str): The CVSS vector string.
        attack_vector (Literal["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]): Attack vector.
        attack_complexity (Literal["HIGH", "LOW"]): Complexity of the attack.
        privileges_required (Literal["NONE", "LOW", "HIGH"]): Required privileges to exploit.
        user_interaction (Literal["NONE", "REQUIRED"]): Whether user interaction is needed.
        scope (Literal["UNCHANGED", "CHANGED"]): Whether a scope change occurs.
        confidentiality_impact (Literal["NONE", "LOW", "HIGH"]): Impact on confidentiality.
        integrity_impact (Literal["NONE", "LOW", "HIGH"]): Impact on integrity.
        availability_impact (Literal["NONE", "LOW", "HIGH"]): Impact on availability.
        base_score (float): Base CVSS score.
        base_severity (SeverityType): Base severity rating (e.g., 'LOW', 'HIGH').

    """

    version: Literal["3.1"] = Field(..., description="CVSS version: 3.1")
    vector_string: str = Field(alias="vectorString", description="CVSS v3.1 vector string.")
    attack_vector: Literal["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"] = Field(
        alias="attackVector",
        description="Indicates how the vulnerability can be exploited (attack vector).",
    )
    attack_complexity: Literal["HIGH", "LOW"] = Field(
        alias="attackComplexity", description="Complexity of executing an attack."
    )
    privileges_required: Literal["NONE", "LOW", "HIGH"] = Field(
        alias="privilegesRequired", description="Privileges required by an attacker."
    )
    user_interaction: Literal["NONE", "REQUIRED"] = Field(
        alias="userInteraction", description="Indicates if user interaction is required."
    )
    scope: Literal["UNCHANGED", "CHANGED"] = Field(
        ..., description="Whether exploitation affects resources beyond the vulnerable component."
    )
    confidentiality_impact: Literal["NONE", "LOW", "HIGH"] = Field(
        alias="confidentialityImpact", description="Impact on confidentiality if exploited."
    )
    integrity_impact: Literal["NONE", "LOW", "HIGH"] = Field(
        alias="integrityImpact", description="Impact on integrity if exploited."
    )
    availability_impact: Literal["NONE", "LOW", "HIGH"] = Field(
        alias="availabilityImpact", description="Impact on availability if exploited."
    )
    base_score: ScoreType = Field(alias="baseScore", description="CVSS base score (0.0 - 10.0).")
    base_severity: SeverityType = Field(
        alias="baseSeverity", description="Severity rating based on the base score."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCvssV31(BaseModel):
    """CVSS v3.1 scoring record provided by a source.

    Contains the CVSS v3.1 data and optional exploitability and impact sub-scores.

    Attributes:
        source (str): Organization that provided the CVSS data.
        type (Literal["Primary", "Secondary"]): Whether the source is primary (provider-level) or secondary.
        cvss_data (CvssV31Data): CVSS v3.1 metric details.
        exploitability_score (Optional[float]): Exploitability sub-score (0.0 - 10.0).
        impact_score (Optional[float]): Impact sub-score (0.0 - 10.0).

    """

    source: str = Field(..., description="Organization providing CVSS v3.1 metrics.")
    type: Literal["Primary", "Secondary"] = Field(
        ..., description="Indicates whether the source is primary or secondary."
    )
    cvss_data: NistNvdCvssV31Data = Field(alias="cvssData", description="CVSS v3.1 metric details.")
    exploitability_score: ScoreType | None = Field(
        alias="exploitabilityScore", default=None, description="Exploitability sub-score."
    )
    impact_score: ScoreType | None = Field(
        alias="impactScore", default=None, description="Impact sub-score."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCvssV2Data(BaseModel):
    """CVSS v2.0 metric data describing severity and exploitability.

    Attributes:
        version (Literal["2.0"]): CVSS version number.
        vector_string (str): The CVSS v2 vector string.
        access_vector (Literal["NETWORK", "ADJACENT_NETWORK", "LOCAL"]): Context of access required.
        access_complexity (Literal["HIGH", "MEDIUM", "LOW"]): Complexity of the required attack.
        authentication (Literal["MULTIPLE", "SINGLE", "NONE"]): Authentication requirements.
        confidentiality_impact (Literal["NONE", "PARTIAL", "COMPLETE"]): Confidentiality impact if exploited.
        integrity_impact (Literal["NONE", "PARTIAL", "COMPLETE"]): Integrity impact if exploited.
        availability_impact (Literal["NONE", "PARTIAL", "COMPLETE"]): Availability impact if exploited.
        base_score (float): Base CVSS v2 score.

    """

    version: Literal["2.0"] = Field(..., description="CVSS version: 2.0")
    vector_string: str = Field(alias="vectorString", description="CVSS v2 vector string.")
    access_vector: Literal["NETWORK", "ADJACENT_NETWORK", "LOCAL"] = Field(
        alias="accessVector", description="Access vector for CVSS v2."
    )
    access_complexity: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        alias="accessComplexity", description="Attack complexity for CVSS v2."
    )
    authentication: Literal["MULTIPLE", "SINGLE", "NONE"] = Field(
        ..., description="Required authentication level for exploitation."
    )
    confidentiality_impact: Literal["NONE", "PARTIAL", "COMPLETE"] = Field(
        alias="confidentialityImpact", description="Confidentiality impact."
    )
    integrity_impact: Literal["NONE", "PARTIAL", "COMPLETE"] = Field(
        alias="integrityImpact", description="Integrity impact."
    )
    availability_impact: Literal["NONE", "PARTIAL", "COMPLETE"] = Field(
        alias="availabilityImpact", description="Availability impact."
    )
    base_score: ScoreType = Field(alias="baseScore", description="Base CVSS v2 score (0.0 - 10.0).")

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCvssV2(BaseModel):
    """CVSS v2.0 scoring record provided by a source.

    Attributes:
        source (str): Organization that provided the CVSS v2 data.
        type (Literal["Primary", "Secondary"]): Whether the source is primary or secondary.
        cvss_data (CvssV2Data): CVSS v2 metric details.
        base_severity (SeverityType): Severity rating determined by CVSS v2 base score.
        exploitability_score (Optional[float]): CVSS v2 exploitability sub-score.
        impact_score (Optional[float]): CVSS v2 impact sub-score.
        ac_insuf_info (Optional[bool]): Indicates if access complexity is insufficient.
        obtain_all_privilege (Optional[bool]): If exploitation obtains all privileges.
        obtain_user_privilege (Optional[bool]): If exploitation obtains user-level privileges.
        obtain_other_privilege (Optional[bool]): If exploitation obtains other privileges.
        user_interaction_required (Optional[bool]): If user interaction is required.

    """

    source: str = Field(..., description="Organization providing CVSS v2 metrics.")
    type: Literal["Primary", "Secondary"] = Field(
        ..., description="Indicates if the source is primary or secondary."
    )
    cvss_data: NistNvdCvssV2Data = Field(
        alias="cvssData", description="Detailed CVSS v2.0 metrics."
    )
    base_severity: SeverityType = Field(
        alias="baseSeverity", description="Base severity rating from CVSS v2."
    )
    exploitability_score: ScoreType | None = Field(
        alias="exploitabilityScore", default=None, description="CVSS v2 exploitability sub-score."
    )
    impact_score: ScoreType | None = Field(
        alias="impactScore", default=None, description="CVSS v2 impact sub-score."
    )
    ac_insuf_info: bool | None = Field(
        alias="acInsufInfo", default=None, description="Indicates access complexity insufficiency."
    )
    obtain_all_privilege: bool | None = Field(
        alias="obtainAllPrivilege",
        default=None,
        description="True if all privileges can be obtained.",
    )
    obtain_user_privilege: bool | None = Field(
        alias="obtainUserPrivilege",
        default=None,
        description="True if user-level privileges obtained.",
    )
    obtain_other_privilege: bool | None = Field(
        alias="obtainOtherPrivilege", default=None, description="True if other privileges obtained."
    )
    user_interaction_required: bool | None = Field(
        alias="userInteractionRequired",
        default=None,
        description="True if user interaction needed.",
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdMetrics(BaseModel):
    """Encapsulates CVSS metrics for a CVE, including CVSSv2 and/or CVSSv3.1.

    This object is optional and only present if a CVE has been analyzed and
    metrics are available.

    Attributes:
        cvss_metric_v31 (Optional[List[CvssV31]]): CVSS v3.1 scoring records.
        cvss_metric_v2 (Optional[List[CvssV2]]): CVSS v2.0 scoring records.

    """

    cvss_metric_v31: list[NistNvdCvssV31] | None = Field(
        alias="cvssMetricV31",
        default=None,
        description="List of CVSS v3.1 metric records if available.",
    )
    cvss_metric_v2: list[NistNvdCvssV2] | None = Field(
        alias="cvssMetricV2",
        default=None,
        description="List of CVSS v2 metric records if available.",
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCveItem(BaseModel):
    """Represents a single CVE entry with detailed vulnerability data as per the NVD schema.

    According to NVD:
    - Required fields: id, published, lastModified, references, descriptions
    - Optional fields: vulnStatus, evaluatorComment, evaluatorSolution, evaluatorImpact, cisaExploitAdd,
      cisaActionDue, cisaRequiredAction, cisaVulnerabilityName, cveTags, metrics, weaknesses, configurations,
      vendorComments

    Attributes:
        id (str): CVE identifier (e.g., CVE-2021-12345). REQUIRED.
        source_identifier (str): Identifier for the source of the CVE. REQUIRED.
        vuln_status (Optional[str]): The CVE's status in the NVD.
        published (datetime): When the CVE was published to the NVD. REQUIRED.
        last_modified (datetime): When the CVE was last modified in the NVD. REQUIRED.
        evaluator_comment (Optional[str]): Additional analysis or notes by an evaluator.
        evaluator_solution (Optional[str]): Guidance on remediation or solutions, if provided.
        evaluator_impact (Optional[str]): Additional context on the impact, if provided.
        cisa_exploit_add (Optional[datetime]): Date when the CVE was added to CISA KEV Catalog, if applicable.
        cisa_action_due (Optional[datetime]): Date by which FCEB agencies must complete required actions.
        cisa_required_action (Optional[str]): Required action as per CISA KEV Catalog, if applicable.
        cisa_vulnerability_name (Optional[str]): Vulnerability name from CISA KEV Catalog.
        cve_tags (Optional[List[CveTag]]): Tags providing contextual information about the CVE.
        descriptions (List[LangString]): Descriptions of the CVE in one or more languages. REQUIRED.
        references (List[Reference]): References providing supplemental information. REQUIRED.
        metrics (Optional[Metrics]): CVSS metrics and scores for the CVE, if analyzed.
        weaknesses (Optional[List[Weakness]]): Weaknesses (e.g., CWE) associated with the CVE.
        configurations (Optional[List[Configuration]]): Affected product configurations.
        vendor_comments (Optional[List[VendorComment]]): Official vendor comments, if any.

    """

    id: Annotated[str, constr(pattern=r"^CVE-\d{4}-\d{4,}$")] = Field(
        ...,
        description="Unique CVE identifier matching the pattern CVE-YYYY-#####, e.g., CVE-2021-1234",
    )
    source_identifier: str = Field(
        alias="sourceIdentifier", description="Identifier of the CVE source (e.g., CNA or NVD)."
    )
    vuln_status: str | None = Field(
        alias="vulnStatus", default=None, description="The vulnerability status in NVD."
    )
    published: datetime = Field(..., description="Date and time the CVE was published to the NVD.")
    last_modified: datetime = Field(
        alias="lastModified", description="Date and time the CVE was last modified in the NVD."
    )
    evaluator_comment: str | None = Field(
        alias="evaluatorComment",
        default=None,
        description="Additional evaluator-provided comments.",
    )
    evaluator_solution: str | None = Field(
        alias="evaluatorSolution",
        default=None,
        description="Evaluator-provided remediation or solution guidance.",
    )
    evaluator_impact: str | None = Field(
        alias="evaluatorImpact",
        default=None,
        description="Evaluator-provided context on the impact.",
    )
    cisa_exploit_add: datetime | None = Field(
        alias="cisaExploitAdd",
        default=None,
        description="Date the CVE was added to the CISA KEV Catalog.",
    )
    cisa_action_due: datetime | None = Field(
        alias="cisaActionDue",
        default=None,
        description="Deadline date for required CISA action on the CVE.",
    )
    cisa_required_action: str | None = Field(
        alias="cisaRequiredAction",
        default=None,
        description="Action required by CISA on the vulnerability.",
    )
    cisa_vulnerability_name: str | None = Field(
        alias="cisaVulnerabilityName",
        default=None,
        description="Name of the vulnerability in the CISA KEV Catalog.",
    )
    cve_tags: list[NistNvdCveTag] | None = Field(
        alias="cveTags",
        default=None,
        description="Tags for additional CVE context (e.g., disputed).",
    )
    descriptions: list[NistNvdLangString] = Field(
        ..., description="List of localized CVE descriptions."
    )
    references: list[NistNvdReference] = Field(
        ..., description="List of references providing supplemental data."
    )
    metrics: NistNvdMetrics | None = Field(
        None, description="CVSS metrics and scores, if available."
    )
    weaknesses: list[NistNvdWeakness] | None = Field(
        None, description="Associated weaknesses (e.g., CWE) for the CVE."
    )
    configurations: list[NistNvdConfiguration] | None = Field(
        None, description="Product configuration applicability."
    )
    vendor_comments: list[NistNvdVendorComment] | None = Field(
        alias="vendorComments",
        default=None,
        description="Official comments from vendors about the CVE.",
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdDefCveItem(BaseModel):
    """Wrapper object containing a single CVE item.

    Attributes:
        cve (CveItem): The CVE item containing all vulnerability details.

    """

    cve: NistNvdCveItem = Field(..., description="A single CVE item as defined by the NVD schema.")

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCveResponse(BaseModel):
    """Represents the NVD API response for CVE data queries.

    According to NVD:
    - Required objects: resultsPerPage, startIndex, totalResults, format, version, timestamp, vulnerabilities
    - The `vulnerabilities` array contains `DefCveItem` objects with CVE data.

    Attributes:
        results_per_page (int): Number of CVE returned per response.
        start_index (int): Index from which CVE are returned (useful for pagination).
        total_results (int): Total number of CVE matching the query criteria.
        format (str): Format of the response (e.g., JSON).
        version (str): Version of the NVD API.
        timestamp (datetime): When the response was generated.
        vulnerabilities (List[DefCveItem]): Array of returned CVE items, each containing a `cve` object.

    """

    results_per_page: int = Field(
        alias="resultsPerPage", description="Number of CVE included per response page."
    )
    start_index: int = Field(
        alias="startIndex", description="Index of the first returned CVE for pagination."
    )
    total_results: int = Field(
        alias="totalResults", description="Total number of CVE matching the query."
    )
    format: str = Field(..., description="Format of the response, e.g., 'JSON'.")
    version: str = Field(..., description="Version of the NVD API schema.")
    timestamp: datetime = Field(..., description="Timestamp of when this response was generated.")
    vulnerabilities: list[NistNvdDefCveItem] = Field(
        alias="vulnerabilities", description="List of CVE items returned by NVD."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdChangeDetail(BaseModel):
    """Describes a single detail of a historical change to a CVE record.

    Attributes:
        action (str): The action taken (e.g., ADD, MODIFY, DELETE).
        type (str): The type of data field changed.
        old_value (Optional[str]): Previous value before the change.
        new_value (Optional[str]): New value after the change.

    """

    action: str = Field(
        ..., description="Action performed on the CVE field (e.g., 'ADD', 'DELETE')."
    )
    type: str = Field(..., description="Type of field that was changed (e.g., 'description').")
    old_value: str | None = Field(
        alias="oldValue", default=None, description="Value before the change."
    )
    new_value: str | None = Field(
        alias="newValue", default=None, description="Value after the change."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdChange(BaseModel):
    """Represents a single CVE change event from the NVD historical record.

    Attributes:
        cve_id (str): The CVE identifier to which the changes apply.
        event_name (str): Name or label for the change event.
        cve_change_id (str): Unique identifier for this change event.
        source_identifier (str): Identifier of the source reporting or causing the change.
        created (datetime): When the change event was recorded.
        details (List[ChangeDetail]): One or more details describing the nature of the change.

    """

    cve_id: str = Field(alias="cveId", description="CVE identifier for the changed record.")
    event_name: str = Field(alias="eventName", description="Name of the event (change action).")
    cve_change_id: str = Field(alias="cveChangeId", description="Unique ID of the change event.")
    source_identifier: str = Field(
        alias="sourceIdentifier", description="Source identifier for this change event."
    )
    created: datetime = Field(..., description="Timestamp when the change was recorded.")
    details: list[NistNvdChangeDetail] = Field(
        ..., description="List of changes made to the CVE record."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCveChangeItem(BaseModel):
    """Container object holding a single CVE change event.

    Attributes:
        change (Change): The details of the CVE change event.

    """

    change: NistNvdChange = Field(..., description="A single historical change event for a CVE.")

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class NistNvdCveHistoryResponse(BaseModel):
    """Represents the NVD API response for CVE change history queries.

    Attributes:
        results_per_page (int): Number of change events per page.
        start_index (int): Index of the first returned change event.
        total_results (int): Total number of change events matching the query.
        format (str): Response format (e.g., JSON).
        version (str): NVD API version.
        timestamp (datetime): When the response was generated.
        cve_changes (List[CveChangeItem]): List of change events related to CVEs.

    """

    results_per_page: int = Field(
        alias="resultsPerPage", description="Number of change events per response page."
    )
    start_index: int = Field(
        alias="startIndex", description="Index of the first returned change event for pagination."
    )
    total_results: int = Field(
        alias="totalResults", description="Total number of matching change events."
    )
    format: str = Field(..., description="Format of the response (e.g., 'JSON').")
    version: str = Field(..., description="Version of the NVD API schema.")
    timestamp: datetime = Field(
        ..., description="Timestamp of when this history response was generated."
    )
    cve_changes: list[NistNvdCveChangeItem] = Field(
        alias="cveChanges", description="List of CVE change events returned by NVD."
    )

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)
