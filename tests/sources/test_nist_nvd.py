import os
import pytest
from datetime import datetime
from elf import NistNvdApiClient
from elf import NistNvdCveResponse

NIST_NVD_API_KEY = os.getenv("NIST_NVD_API_KEY")

@pytest.mark.asyncio
async def test_nvd_cve_fetch():
    """Test fetching a specific CVE from the NVD API (known vulnerability)."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        response: NistNvdCveResponse = await client.get_cve("CVE-2021-34527")
        assert response.total_results > 0, "Expected at least one result"
        vulnerability = response.vulnerabilities[0].cve
        assert vulnerability.id == "CVE-2021-34527", "CVE ID mismatch"
        assert len(vulnerability.descriptions) > 0, "Missing vulnerability descriptions"

@pytest.mark.asyncio
async def test_nvd_cve_search():
    """Test searching for CVEs with a general keyword."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        generator = client.search_cves(keyword_search="print spooler", results_per_page=10)
        found = False
        async for page in generator:
            try:
                assert len(page.vulnerabilities) <= 10, "Page size exceeds limit"
                if page.vulnerabilities:
                    found = True
                    break
            finally:
                await generator.aclose()
        assert found, "No CVEs found for keyword 'print spooler'"

@pytest.mark.asyncio
async def test_nvd_fetch_specific_cve():
    """Test fetching a specific CVE and verifying expected structure."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        response = await client.get_cve("CVE-2021-34527")
        assert response.results_per_page == 1, "Results per page should be 1"
        assert response.vulnerabilities[0].cve.id == "CVE-2021-34527", "CVE ID mismatch"

@pytest.mark.asyncio
async def test_nvd_search_with_filters():
    """Test searching for CVEs using keyword and publication date filters."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        start_date = datetime(2021, 7, 1)
        end_date = datetime(2021, 7, 5)
        generator = client.search_cves(keyword_search="Microsoft", pub_start_date=start_date, pub_end_date=end_date, results_per_page=20)
        found = False
        async for page in generator:
            try:
                if page.vulnerabilities:
                    found = True
                    break
            finally:
                await generator.aclose()
        assert found, "No CVEs found for given filters"

@pytest.mark.asyncio
async def test_nvd_paginated_search():
    """Test paginated search results from the NVD API by limiting results."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        generator = client.search_cves(keyword_search="Windows", results_per_page=2)
        total_results = 0
        async for page in generator:
            try:
                assert len(page.vulnerabilities) <= 2, "Page size exceeds limit"
                total_results += len(page.vulnerabilities)
                if total_results >= 4:
                    break
            finally:
                await generator.aclose()
        assert total_results > 0, "Expected at least some results for 'Windows'"

@pytest.mark.asyncio
async def test_nvd_cve_change_history():
    """Test fetching CVE change history for a known CVE."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        generator = client.get_cve_history_paginated(cve_id="CVE-2021-34527", results_per_page=2)
        found_changes = False
        async for page in generator:
            try:
                if page.cve_changes:
                    found_changes = True
                    break
            finally:
                await generator.aclose()
        assert found_changes, "No changes found for CVE-2021-34527"

@pytest.mark.asyncio
async def test_nvd_no_results():
    """Test searching for a non-existent CVE or unlikely keyword to get no results."""
    async with NistNvdApiClient(api_key=NIST_NVD_API_KEY) as client:
        generator = client.search_cves(keyword_search="ThisShouldNotMatchAnythingLikely", results_per_page=10)
        empty = True
        async for page in generator:
            if page.vulnerabilities:
                empty = False
                break
        assert empty, "Expected no results for a nonsense keyword"
