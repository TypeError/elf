<div align="center">

# ELF (Exposure Lookup Framework)

**Bringing together vulnerability intelligence from multiple sources into a single, harmonious API.**

[![PyPI Version](https://img.shields.io/pypi/v/elf.svg)](https://pypi.org/project/elf/)
[![Python Versions](https://img.shields.io/pypi/pyversions/elf.svg)](https://pypi.org/project/elf/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Downloads](https://pepy.tech/badge/elf)](https://pepy.tech/project/elf)
[![License](https://img.shields.io/pypi/l/elf.svg)](https://github.com/TypeError/elf/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/TypeError/elf.svg)](https://github.com/TypeError/elf/stargazers)

</div>

---

**ELF** (Exposure Lookup Framework) is a modern Python library that streamlines the **aggregation**, **parsing**, and **analysis** of vulnerability data from multiple trusted sources, including:

- **[CISA KEV](#cisa-kev)** – Authoritative catalog of actively exploited vulnerabilities
- **[FIRST EPSS](#first-epss)** – Predictive scoring system to gauge exploitation likelihood
- **[NIST NVD](#nist-nvd)** – Comprehensive CVE database maintained by the National Institute of Standards and Technology

**Supported Python Versions**: 3.11 and above

ELF helps you:

- Effortlessly query and consolidate vulnerability information
- Apply advanced filters, searches, and scoring systems
- Validate structured data using Pydantic models
- Integrate insights into dashboards, CI/CD pipelines, and data-driven security workflows

All with a clean, Pythonic, **async-first** interface. If you’re new to asynchronous programming in Python, check out the [asyncio documentation](https://docs.python.org/3/library/asyncio.html).

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Supported Data Sources](#supported-data-sources)
  - [CISA KEV](#cisa-kev)
  - [FIRST EPSS](#first-epss)
  - [NIST NVD](#nist-nvd)
- [Usage](#usage)
  - [Quick Start](#quick-start)
  - [Advanced Examples](#advanced-examples)
- [Attribution and Usage Guidelines](#attribution-and-usage-guidelines)
- [Special Thanks to Solos](#special-thanks-to-solos)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- ✅ **Query vulnerability data from multiple sources**

  - **CISA KEV**: Known Exploited Vulnerabilities catalog
  - **FIRST EPSS**: Exploit Prediction Scoring System for prioritization
  - **NIST NVD**: National Vulnerability Database for comprehensive CVE details

- 🔍 **Advanced filtering and searching**

  - Filter by date, CVE IDs, scores, severity, and more

- 🛠️ **Pydantic-based data validation**

  - Robust validation for structured data handling

- 📈 **Pagination and bulk data fetching**

  - Efficiently process large datasets

- 🚀 **Integration-ready**
  - Seamlessly integrate into dashboards, CI/CD pipelines, or analytics workflows

---

## Installation

### Using `pip`

```bash
pip install elf
```

### Using `uv`

If you use [uv](https://docs.astral.sh/uv/) for package management:

```bash
uv add elf
```

---

## Supported Data Sources

### CISA KEV

The [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog provides an authoritative list of vulnerabilities actively exploited in the wild. With ELF, you can programmatically query and analyze these vulnerabilities:

```python
from elf import CisaKevApiClient

async with CisaKevApiClient() as client:
    kev_data = await client.get_kev_json()
    print(f"The CISA KEV catalog contains {len(kev_data.vulnerabilities)} actively exploited vulnerabilities.")
```

### FIRST EPSS

The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss) predicts the likelihood of a CVE being exploited. ELF offers a straightforward interface to retrieve EPSS scores:

```python
from elf import FirstEpssApiClient

async with FirstEpssApiClient() as client:
    epss_scores = await client.get_scores_json(["CVE-2023-1234"])
    for score in epss_scores.data:
        print(f"CVE ID: {score.cve}, EPSS Score: {score.epss}, Percentile: {score.percentile}")
```

### NIST NVD

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) from NIST is among the most comprehensive CVE data sources. ELF integrates natively with the NVD API:

```python
from elf import NistNvdApiClient

async with NistNvdApiClient() as client:
    cve_details = await client.get_cve("CVE-2023-1234")
    cve = cve_details.vulnerabilities[0].cve
    print(f"CVE ID: {cve.id}")
    print(f"Description: {next((desc.value for desc in cve.descriptions if desc.lang == 'en'), 'No description available')}")
    print(f"Published: {cve.published}, Last Modified: {cve.last_modified}")
```

---

## Usage

### Quick Start

Here’s a simple snippet to fetch CSV data from **CISA KEV**:

```python
import asyncio
from elf import CisaKevApiClient

async def main():
    async with CisaKevApiClient() as client:
        kev_csv = await client.get_kev_csv()
        print(kev_csv)  # Raw CSV data

asyncio.run(main())
```

### Advanced Examples

#### Search and Paginate NIST NVD Data

```python
import asyncio
import os
from datetime import datetime

from elf import NistNvdApiClient

NIST_NVD_API_KEY = os.getenv("NIST_NVD_API_KEY")


async def main():
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        generator = client.search_cves(
            keyword_search="remote code execution",
            cvss_v3_severity="CRITICAL",
            results_per_page=5,
            pub_start_date=datetime(2024, 11, 1),
            pub_end_date=datetime(2024, 12, 1),
        )

        async for page in generator:
            print(f"Processing {len(page.vulnerabilities)} vulnerabilities...")
            for vuln in page.vulnerabilities:
                print(f"ID: {vuln.cve.id}")
                print(
                    f"Description: {next((d.value for d in vuln.cve.descriptions if d.lang == 'en'), 'No description available')}"
                )
                print(
                    f"CVSS v3 Score: {vuln.cve.metrics.cvss_metric_v31[0].cvss_data.base_score if vuln.cve.metrics and vuln.cve.metrics.cvss_metric_v31 else 'N/A'}"
                )
                print("-" * 40)


asyncio.run(main())
```

#### Fetch and Process Paginated CISA KEV Data

```python
from elf import CisaKevApiClient

async def fetch_paginated_kev_data():
    async with CisaKevApiClient() as client:
        async for kev_chunk in client.get_kev_json_paginated(chunk_size=500):
            print(f"Processing {len(kev_chunk.vulnerabilities)} vulnerabilities")
```

#### Combine Data from Multiple Sources

```python
from elf import CisaKevApiClient, FirstEpssApiClient, NistNvdApiClient


async def combine_data_sources():
    """Combine data from CISA KEV, FIRST EPSS, and NIST NVD."""
    async with (
        CisaKevApiClient() as cisa_client,
        FirstEpssApiClient() as epss_client,
        NistNvdApiClient() as nvd_client,
    ):
        # Step 1: Fetch vulnerabilities from CISA KEV
        kev_data = await cisa_client.get_kev_json()
        print(f"Fetched {len(kev_data.vulnerabilities)} vulnerabilities from the CISA KEV catalog.")

        # Step 2: Get EPSS scores for the first 5 vulnerabilities
        epss_scores = await epss_client.get_scores_json(
            cve_ids=[v.cve_id for v in kev_data.vulnerabilities[:5]]
        )
        print(f"Retrieved EPSS scores for {len(epss_scores.data)} CVEs.")

        # Step 3: Fetch NVD details for each CVE and combine insights
        for score in epss_scores.data:
            nvd_details = await nvd_client.get_cve(score.cve)
            nvd_cve = nvd_details.vulnerabilities[0].cve

            print(f"CVE ID: {score.cve}")
            print(f"EPSS Score: {score.epss}, Percentile: {score.percentile}")
            print(
                f"Description: {next((d.value for d in nvd_cve.descriptions if d.lang == 'en'), 'No description available')}"
            )
            print(f"Published: {nvd_cve.published}, Last Modified: {nvd_cve.last_modified}")
            print("-" * 40)
```

---

## Attribution and Usage Guidelines

When using data from **CISA KEV**, **FIRST EPSS**, or **NIST NVD**, you must comply with their respective terms of use, attribution requirements, and usage agreements. Here’s a summary for each source:

### CISA KEV Attribution and Usage

The [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) are provided under [Creative Commons 0 1.0 License (CC0)](https://creativecommons.org/publicdomain/zero/1.0/).

- **Key Requirements**:

  - **Free to Use**: Data can be used in any lawful manner.
  - **Restrictions**:
    - Do not use the CISA logo or DHS seal.
    - Third-party links in the KEV database are governed by external policies.

- **Further Information**:
  - [CISA KEV License](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)

### FIRST EPSS Attribution and Usage

The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss) provides a predictive score for exploitation likelihood.

- **Key Requirements**:
  - **Attribution**:  
    Cite EPSS data, e.g.,  
    _Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid, (2021). Digital Threats Research and Practice, 2(3)._  
    Or link to [EPSS](https://www.first.org/epss).
  - **Usage Agreement**:  
    Follow [EPSS Usage Guidelines](https://www.first.org/epss/user-guide).

### NIST NVD Attribution and Usage

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) is a public resource from [NIST](https://www.nist.gov).

- **Key Requirements**:

  - **Attribution**:  
    Display a notice such as:
    > _"This product uses the NVD API but is not endorsed or certified by the NVD."_
  - **Use of NVD Name**:
    - You may reference the “NVD” name to identify the data source but **not** to imply endorsement.

- **Further Information**:
  - [NVD Developers: Start Here](https://nvd.nist.gov/developers/start-here)
  - [NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use)

---

## Special Thanks to Solos

A heartfelt thank you to [**Solos**](https://github.com/solos) for donating the `elf` package name on PyPI. Your generosity helps make this project possible and supports innovation in the Python community!

---

## Contributing

We welcome contributions! Issues and PRs are greatly appreciated—feel free to jump in and help make ELF even better.

---

## License

This project is licensed under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for details.
