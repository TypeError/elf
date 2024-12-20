# type: ignore

import pytest
from datetime import datetime
from elf import CisaKevApiClient
from elf import CisaKevVulnerability, CisaKevCatalog
import csv
from io import StringIO

@pytest.mark.asyncio
async def test_cisa_kev_json_fetch():
    """Test fetching JSON data from the CISA KEV API and validating basic fields."""
    async with CisaKevApiClient() as client:
        kev_data = await client.get_kev_json()
        assert isinstance(kev_data, CisaKevCatalog), "Response should be a CisaKevCatalog"
        assert hasattr(kev_data, "catalog_version"), "Catalog version is missing"
        assert hasattr(kev_data, "date_released"), "dateReleased is missing"
        assert hasattr(kev_data, "vulnerabilities"), "vulnerabilities field is missing"

        assert len(kev_data.vulnerabilities) > 0, "No vulnerabilities found in KEV data"

        # Check a few fields of the first vulnerability
        first_vuln = kev_data.vulnerabilities[0]
        assert isinstance(first_vuln, CisaKevVulnerability), "Wrong type for a vulnerability item"
        assert first_vuln.cve_id.startswith("CVE-"), "First vulnerability has invalid CVE format"
        assert first_vuln.vendor_project, "Vendor/Project is missing"
        assert first_vuln.product, "Product is missing"
        assert first_vuln.date_added, "dateAdded is missing"
        # Ensure date_added is a proper date
        datetime.strptime(str(first_vuln.date_added), "%Y-%m-%d")

@pytest.mark.asyncio
async  def test_cisa_kev_csv_fetch():
    """Test fetching CSV data from the CISA KEV API and validating CSV structure."""
    async with CisaKevApiClient() as client:
        kev_csv = await client.get_kev_csv()
        assert kev_csv, "CSV response is empty"

        decoded_csv = kev_csv.decode("utf-8")
        csv_reader = csv.reader(StringIO(decoded_csv))
        lines = list(csv_reader)

        assert len(lines) > 1, "CSV should have headers and data lines"
        header = lines[0]
        first_data = lines[1]

        assert "cveID" in header, "CSV header is invalid"
        assert "vendorProject" in header, "CSV header missing vendorProject column"
        assert len(first_data) == len(header), "First data line doesn't match header column count"

@pytest.mark.asyncio
async def test_cisa_kev_json_paginated():
    """Test the paginated fetching of KEV data and verify chunks."""
    async with CisaKevApiClient() as client:
        chunks = []
        async for chunk in client.get_kev_json_paginated(chunk_size=50):
            assert len(chunk.vulnerabilities) <= 50, "Chunk size exceeds limit"
            chunks.append(chunk)
            # Just break early after a few chunks to avoid huge downloads
            if len(chunks) >= 3:
                break

        assert len(chunks) > 0, "No chunks returned in paginated KEV data"

@pytest.mark.asyncio
async def test_cisa_kev_json_integrity():
    """Test that the KEV JSON data is consistent and vulnerabilities have expected fields."""
    async with CisaKevApiClient() as client:
        kev_data = await client.get_kev_json()

        # Check random fields on a few vulnerabilities
        for vuln in kev_data.vulnerabilities[:5]:
            assert vuln.cve_id.startswith("CVE-"), f"Invalid CVE format: {vuln.cve_id}"
            assert vuln.vulnerability_name, "Vulnerability name is missing"
            assert vuln.short_description, "Short description is missing"
            # date_added should be a valid date
            assert vuln.date_added, "dateAdded is missing"
            datetime.strptime(str(vuln.date_added), "%Y-%m-%d")

@pytest.mark.asyncio
async def test_cisa_kev_known_cve():
    """Test to verify that a known CVE is present in the KEV data."""
    async with CisaKevApiClient() as client:
        kev_data = await client.get_kev_json()
        # CVE-2021-34527 (PrintNightmare) is commonly in the KEV list
        found = any(v.cve_id == "CVE-2021-34527" for v in kev_data.vulnerabilities)
        assert found, "Known CVE (CVE-2021-34527) not found in KEV data"

@pytest.mark.asyncio
async def test_cisa_kev_json_small_chunk():
    """Test pagination with a very small chunk size to ensure correctness and uniqueness of pages."""
    async with CisaKevApiClient() as client:
        seen_cves = set()
        count_chunks = 0
        async for chunk in client.get_kev_json_paginated(chunk_size=1):
            assert len(chunk.vulnerabilities) == 1, "Chunk size is not respected with chunk_size=1"
            cve = chunk.vulnerabilities[0].cve_id
            assert cve not in seen_cves, "Duplicate CVE found in subsequent chunks"
            seen_cves.add(cve)
            count_chunks += 1
            if count_chunks >= 5:
                break
        assert count_chunks > 0, "No chunks returned when using small chunk_size=1"

@pytest.mark.asyncio
async def test_cisa_kev_json_large_chunk():
    """Test pagination with a large chunk size, ensuring that it doesn't fail and returns at least one chunk."""
    async with CisaKevApiClient() as client:
        chunks = []
        async for chunk in client.get_kev_json_paginated(chunk_size=5000):
            chunks.append(chunk)
            break  # Just verify we get at least one chunk
        assert len(chunks) == 1, "Should return at least one chunk even with a large chunk_size"
        assert len(chunks[0].vulnerabilities) > 0, "Large chunk returned no vulnerabilities"
