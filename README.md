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

**Supported Python Versions**: 3.10 and above

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
  - [CISA KEV Examples](#cisa-kev-examples)
  - [FIRST EPSS Examples](#first-epss-examples)
  - [NIST NVD Examples](#nist-nvd-examples)
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

The [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog provides an authoritative list of vulnerabilities actively exploited in the wild. ELF enables seamless programmatic access to these datasets.

### FIRST EPSS

The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss) predicts the likelihood of a CVE being exploited. ELF offers interfaces for JSON and CSV retrievals, along with time-series data.

### NIST NVD

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) from NIST is among the most comprehensive CVE data sources. ELF integrates with NVD for CVE details, search functionality, and change history.

---

## Usage

### CISA KEV Examples

```python
import asyncio
from elf import CisaKevApiClient

# Fetch all vulnerabilities in JSON format
async def fetch_all_vulnerabilities():
    async with CisaKevApiClient() as client:
        kev_data = await client.get_kev_json()
        print(f"Catalog Title: {kev_data.catalog_version}")
        print(f"Total Vulnerabilities: {kev_data.count}")

# Fetch vulnerabilities as raw CSV
async def fetch_vulnerabilities_csv():
    async with CisaKevApiClient() as client:
        kev_csv = await client.get_kev_csv()
        with open("kev_data.csv", "wb") as file:
            file.write(kev_csv)
        print("CSV data saved as kev_data.csv")

# Fetch paginated data
async def fetch_paginated_vulnerabilities():
    async with CisaKevApiClient() as client:
        async for chunk in client.get_kev_json_paginated(chunk_size=500):
            print(f"Fetched {len(chunk.vulnerabilities)} vulnerabilities in this chunk.")

# Run examples
async def main():
    await fetch_all_vulnerabilities()
    await fetch_vulnerabilities_csv()
    await fetch_paginated_vulnerabilities()

asyncio.run(main())
```

---

### FIRST EPSS Examples

```python
import asyncio
from elf import FirstEpssApiClient, FirstEpssOrderOption

# Retrieve EPSS scores for specific CVEs
async def fetch_epss_scores():
    async with FirstEpssApiClient() as client:
        scores = await client.get_scores_json(["CVE-2023-1234", "CVE-2023-5678"])
        for score in scores.data:
            print(f"CVE: {score.cve}, Score: {score.epss}, Percentile: {score.percentile}")

# Download full EPSS CSV for a specific date
async def download_full_csv():
    async with FirstEpssApiClient() as client:
        csv_data = await client.download_and_decompress_full_csv_for_date("2023-12-01")
        with open("epss_data.csv", "w") as file:
            file.write(csv_data)
        print("Decompressed CSV saved as epss_data.csv")

# Fetch the highest EPSS scores
async def fetch_highest_epss_scores():
    async with FirstEpssApiClient() as client:
        response = await client.get_cves(order=FirstEpssOrderOption.EPSS_DESC, limit=5)
        print("Top 5 CVEs with the highest EPSS scores:")
        for item in response.data:
            print(f"CVE: {item.cve}, EPSS: {item.epss}, Percentile: {item.percentile}")

# Paginate EPSS data
async def fetch_paginated_epss_scores():
    async with FirstEpssApiClient() as client:
        async for page in client.get_scores_paginated_json(limit_per_request=100, max_records=500):
            for record in page.data:
                print(f"CVE: {record.cve}, Score: {record.epss}")

# Run examples
async def main():
    await fetch_epss_scores()
    await download_full_csv()
    await fetch_highest_epss_scores()
    await fetch_paginated_epss_scores()

asyncio.run(main())
```

---

### NIST NVD Examples

```python
import asyncio
import os
from datetime import datetime

from elf.core.exceptions import ApiClientError
from elf.sources.nist_nvd.client import NistNvdApiClient

NIST_NVD_API_KEY = os.getenv("NIST_NVD_API_KEY")


# Fetch details for a specific CVE
async def fetch_cve_details():
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        cve_data = await client.get_cve("CVE-2021-34527")
        print(f"CVE ID: {cve_data.vulnerabilities[0].cve.id}")
        print(f"Description: {cve_data.vulnerabilities[0].cve.descriptions[0].value}")


# Search CVEs with filters
async def search_cves():
    try:
        async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
            async for page in client.search_cves(
                cpe_name="cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                cvss_v3_severity="HIGH",
                pub_start_date=datetime(2016, 3, 1),
                pub_end_date=datetime(2016, 3, 12),
            ):
                if not page.vulnerabilities:
                    print("No vulnerabilities found for this query.")
                    return
                for vuln in page.vulnerabilities:
                    print(f"CVE ID: {vuln.cve.id}, Published: {vuln.cve.published}")
    except ApiClientError as e:
        print(f"Error during CVE search: {e}")


# Retrieve CVE change history
async def fetch_cve_history():
    try:
        async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
            async for page in client.get_cve_history_paginated(
                cve_id="CVE-2021-34527",
                change_start_date=datetime(2023, 1, 1),
                change_end_date=datetime(2023, 6, 1),
            ):
                if not page.cve_changes:
                    print("No changes found for this CVE.")
                    return
                print(page.cve_changes)
    except ApiClientError as e:
        print(f"Error during CVE history fetch: {e}")


# Run examples
async def main():
    await fetch_cve_details()
    await search_cves()
    await fetch_cve_history()


asyncio.run(main())
```

---

## Attribution and Usage Guidelines

### CISA KEV

Data provided under the [Creative Commons 0 1.0 License (CC0)](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt).

### FIRST EPSS

Usage must adhere to the [FIRST EPSS Usage Guidelines](https://www.first.org/epss/user-guide).

### NIST NVD

Data usage is governed by the [NIST Terms of Use](https://nvd.nist.gov/developers/terms-of-use).

---

## Special Thanks to Solos

Special thanks to [Solos](https://github.com/solos) for donating the `elf` package name on PyPI.

---

## Contributing

Contributions are welcome! Please [open an issue](https://github.com/TypeError/elf/issues) or submit a [pull request](https://github.com/TypeError/elf/pulls) for new features or bug fixes.

---

## License

This project is licensed under the [MIT License](LICENSE).
