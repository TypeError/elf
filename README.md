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

**ELF** (Exposure Lookup Framework) is a modern Python library that streamlines the aggregation, parsing, and analysis of vulnerability data from multiple trusted sources, including:

- **[CISA KEV](#cisa-kev)**: Authoritative catalog of actively exploited vulnerabilities.
- **[FIRST EPSS](#first-epss)**: Predictive scoring system to gauge exploitation likelihood.
- **[NIST NVD](#nist-nvd)**: Comprehensive CVE database maintained by the National Institute of Standards and Technology.

**Supported Python Versions**: ELF supports Python 3.8 and above.

With ELF, you can:

- Effortlessly query and consolidate vulnerability information.
- Apply advanced filters, searches, and scoring systems.
- Validate structured data using Pydantic models.
- Integrate the resulting insights into dashboards, CI/CD pipelines, and data-driven security workflows.

All in a clean, Pythonic, **async-first** interface. If you're new to asynchronous programming in Python, see [asyncio documentation](https://docs.python.org/3/library/asyncio.html).

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
- [Special Thanks to Solos](#-special-thanks-to-solos-)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- ✅ **Query vulnerability data from multiple sources**:
  - **CISA KEV**: Known Exploited Vulnerabilities catalog.
  - **FIRST EPSS**: Exploit Prediction Scoring System for prioritization.
  - **NIST NVD**: National Vulnerability Database for comprehensive CVE details.
- 🔍 **Advanced filtering and searching**:
  - Filter by date, CVE, scores, and more.
- 🛠️ **Pydantic-based data validation**:
  - Robust validation for structured data handling.
- 📈 **Pagination and bulk data fetching support**:
  - Fetch and process large datasets efficiently.
- 🚀 **Integration-ready**:
  - Seamlessly integrate into dashboards, CI/CD pipelines, or analytics workflows.

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

The CISA Known Exploited Vulnerabilities (KEV) catalog provides authoritative data on vulnerabilities actively exploited in the wild. ELF allows you to programmatically query this data for integration and analysis.

```python
from elf import CisaKevApiClient

async with CisaKevApiClient() as client:
    kev_data = await client.get_kev_json()
    print(f"Total vulnerabilities: {len(kev_data.vulnerabilities)}")
```

### FIRST EPSS

FIRST's Exploit Prediction Scoring System (EPSS) predicts the likelihood of a CVE being exploited. ELF provides interfaces for querying EPSS scores.

```python
from elf import FirstEpssApiClient

async with FirstEpssApiClient() as client:
    epss_scores = await client.get_scores_json(["CVE-2023-1234"])
    print(epss_scores.data)
```

### NIST NVD

NIST's National Vulnerability Database offers detailed CVE data. ELF integrates with its API for searching and retrieving CVEs.

```python
from elf import NistNvdApiClient

async with NistNvdApiClient() as client:
    cve_details = await client.get_cve("CVE-2023-1234")
    print(cve_details)
```

---

## Usage

### Quick Start

Here's how to query data from CISA KEV:

```python
import asyncio
from elf import CisaKevApiClient

async def main():
    async with CisaKevApiClient() as client:
        kev_data = await client.get_kev_csv()
        print(f"Total vulnerabilities: {len(kev_data)}")

asyncio.run(main())
```

### Advanced Examples

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
async def combine_data_sources():
    async with (
        CisaKevApiClient() as cisa_client,
        FirstEpssApiClient() as epss_client,
        NistNvdApiClient() as nvd_client,
    ):
        kev_data = await cisa_client.get_kev_json()
        epss_scores = await epss_client.get_scores_json(
            cve_ids=[v.cve_id for v in kev_data.vulnerabilities[0:5]]
        )
        for score in epss_scores.data:
            print(f"EPSS Score for {score.cve}: {score.epss}")
```

---

## Attribution and Usage Guidelines

When using data from **CISA KEV**, **FIRST EPSS**, or **NIST NVD**, you are required to comply with their respective terms of use, attribution requirements, and usage agreements. Below are the details for each source.

### CISA KEV Attribution and Usage

The [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog provides data under the [Creative Commons 0 1.0 License (CC0)](https://creativecommons.org/publicdomain/zero/1.0/).

**Key Requirements**:

- **Free to Use**: Data can be used in any lawful manner.
- **Restrictions**:
  - Do not use the CISA logo or DHS seal.
  - Third-party links in the KEV database are governed by the policies of the linked websites.

**Further Information**:

- [CISA KEV License](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)

### FIRST EPSS Attribution and Usage

The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss) provides predictive scoring to evaluate the likelihood of a CVE being exploited. It is freely available, but certain usage guidelines must be followed.

**Key Requirements**:

- **Attribution**:
  - Cite EPSS data as:  
    _Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid, (2021), Exploit Prediction Scoring System, Digital Threats Research and Practice, 2(3)._
  - Or: _"See EPSS at https://www.first.org/epss"_
- **Usage Agreement**:  
  Follow the [EPSS Usage Guidelines](https://www.first.org/epss/user-guide).

**Further Information**:

- [EPSS Home](https://www.first.org/epss/)

### NIST NVD Attribution and Usage

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) is a public resource provided by the [National Institute of Standards and Technology (NIST)](https://www.nist.gov).

**Key Requirements**:

- **Attribution**:  
  Services or applications using NVD data must display this notice:
  > _"This product uses the NVD API but is not endorsed or certified by the NVD."_
- **Use of NVD Name**:  
  You may reference the NVD name to identify the data source but **not** to imply endorsement of any product, service, or entity.

**Further Information**:

- [Getting Started with NVD](https://nvd.nist.gov/developers/start-here)
- [NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use)

---

## Special Thanks to Solos

A heartfelt thank you to [**Solos**](https://github.com/solos) for generously donating the `elf` package name on PyPI.  
Your contribution helps make this project possible and supports innovation in the Python community!

---

## Contributing

We welcome contributions! Please check out the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started. Issues and PRs are greatly appreciated.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
