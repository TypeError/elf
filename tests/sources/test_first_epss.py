import pytest
from elf import FirstEpssApiClient

@pytest.mark.asyncio
async def test_epss_scores_json_fetch():
    """Test fetching EPSS scores in JSON format with multiple CVEs."""
    async with FirstEpssApiClient() as client:
        epss_data = await client.get_scores_json(["CVE-2022-12345", "CVE-2021-34527"])
        assert epss_data.total > 0, "No EPSS scores found"
        assert len(epss_data.data) > 0, "No data returned"
        for item in epss_data.data:
            assert item.cve.startswith("CVE-"), f"Invalid CVE format in data: {item.cve}"

@pytest.mark.asyncio
async def test_epss_scores_csv_fetch():
    """Test fetching EPSS scores in CSV format."""
    async with FirstEpssApiClient() as client:
        epss_csv = await client.get_scores_csv(["CVE-2022-12345", "CVE-2021-34527"])
        assert epss_csv, "CSV response is empty"
        lines = epss_csv.splitlines()
        assert len(lines) > 1, "CSV should have headers and data"
        header = lines[0].lower()
        assert "cve" in header, "CSV header is invalid"

@pytest.mark.asyncio
async def test_epss_single_cve_fetch():
    """Test fetching EPSS scores for a single known CVE."""
    async with FirstEpssApiClient() as client:
        response = await client.get_score_json("CVE-2021-34527")
        assert response.status == "OK", "API status is not OK"
        # Usually returns one record; check that it matches our CVE
        assert any(item.cve == "CVE-2021-34527" for item in response.data), "Expected CVE not in result"

@pytest.mark.asyncio
async def test_epss_scores_filtering():
    """Test filtering EPSS scores with a threshold. We pick a threshold likely to be met."""
    async with FirstEpssApiClient() as client:
        response = await client.get_scores_json(cve_ids=["CVE-2021-34527", "CVE-2022-12345"], epss_gt=0.1)
        assert response.status == "OK", "API status is not OK"
        assert all(item.epss > 0.1 for item in response.data), "Some EPSS scores do not meet the threshold"

@pytest.mark.asyncio
async def test_epss_scores_paginated():
    """Test fetching EPSS scores with pagination."""
    async with FirstEpssApiClient() as client:
        generator = client.get_scores_paginated_json(limit_per_request=2)
        total_results = 0
        try:
            async for page in generator:
                assert len(page.data) <= 2, "Page size exceeds limit"
                total_results += len(page.data)
                # Stop early to limit test time
                if total_results >= 4:
                    break
        finally:
            await generator.aclose()

        assert total_results > 0, "No results fetched via pagination"

@pytest.mark.asyncio
async def test_epss_no_results():
    """Test EPSS search that likely returns no results (non-existent CVE)."""
    async with FirstEpssApiClient() as client:
        response = await client.get_scores_json(["CVE-9999-9999"])
        # If the CVE doesn't exist, often the API returns empty data set
        assert len(response.data) == 0, "Expected no results for a non-existent CVE"

@pytest.mark.asyncio
async def test_epss_invalid_parameters():
    """Test EPSS with an impossible filter (epss_gt=2.0), expecting no results."""
    async with FirstEpssApiClient() as client:
        # Using epss_gt=2.0 is impossible since EPSS <= 1.0 for all CVEs.
        response = await client.get_scores_json(["CVE-2021-34527"], epss_gt=2.0)
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 0, "Expected no data with an impossible threshold"

@pytest.mark.asyncio
async def test_epss_pagination_real():
    """Test pagination with real data. Stop after a few pages."""
    async with FirstEpssApiClient() as client:
        total_count = 0
        async for page in client.get_scores_paginated_json(limit_per_request=5):
            total_count += len(page.data)
            if total_count > 10:
                break
        assert total_count > 0, "No data returned via pagination, API may have changed"

@pytest.mark.asyncio
async def test_epss_recent_cves():
    """Check that recent CVEs (in the last few days) have some data."""
    async with FirstEpssApiClient() as client:
        # Assuming 'days' filters by recent vulnerabilities
        response = await client.get_recent_cves_json(days=7)
        assert response.status == "OK", "API status not OK for recent CVEs"
        assert len(response.data) > 0, "No recent CVEs found, possibly API changed"

@pytest.mark.asyncio
async def test_epss_common_cves():
    """Ensure common CVEs known for high impact return data."""
    cves = ["CVE-2017-0144", "CVE-2021-34527"]  # well-known vulnerabilities
    async with FirstEpssApiClient() as client:
        response = await client.get_scores_json(cves)
        assert response.status == "OK", "API did not return status OK"
        for cve in cves:
            assert any(item.cve == cve for item in response.data), f"{cve} not found in EPSS data"

@pytest.mark.asyncio
async def test_epss_known_cve_present():
    """Check that a known CVE is present in EPSS data."""
    async with FirstEpssApiClient() as client:
        response = await client.get_score_json("CVE-2017-0144")  # EternalBlue vulnerability
        assert response.status == "OK"
        assert any(item.cve == "CVE-2017-0144" for item in response.data), "Known CVE not present"
