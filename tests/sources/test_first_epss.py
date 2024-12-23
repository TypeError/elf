import pytest
from elf import FirstEpssApiClient, FirstEpssOrderOption
from datetime import datetime

@pytest.mark.asyncio
async def test_epss_batch_scores_fetch():
    """Test fetching EPSS scores in JSON format for multiple CVEs."""
    async with FirstEpssApiClient() as client:
        response = await client.get_scores_json(["CVE-2022-27225", "CVE-2022-27223", "CVE-2022-27218"])
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 3, "Unexpected number of CVEs returned"
        for item in response.data:
            assert item.cve.startswith("CVE-"), f"Invalid CVE format: {item.cve}"

@pytest.mark.asyncio
async def test_epss_single_cve_score_fetch():
    """Test fetching EPSS score for a single CVE on a specific date."""
    async with FirstEpssApiClient() as client:
        response = await client.get_score_json("CVE-2022-26332", date="2022-03-05")
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 1, "Unexpected number of CVEs returned"
        assert response.data[0].cve == "CVE-2022-26332", "Incorrect CVE returned"

@pytest.mark.asyncio
async def test_epss_time_series_cve():
    """Test fetching EPSS scores for a single CVE over the past 30 days."""
    async with FirstEpssApiClient() as client:
        response = await client.get_score_json("CVE-2022-25204", scope="time-series")
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 1, "Unexpected number of CVEs returned"
        assert response.data[0].cve == "CVE-2022-25204", "Incorrect CVE returned"
        assert response.data[0].time_series, "Missing time-series data"
        for ts in response.data[0].time_series:
            assert isinstance(ts.date, datetime), "Invalid date format in time-series data"

@pytest.mark.asyncio
async def test_epss_highest_scoring_cves():
    """Test fetching top CVEs with the highest EPSS scores."""
    async with FirstEpssApiClient() as client:
        response = await client.get_cves(order=FirstEpssOrderOption.EPSS_DESC, limit=5)
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 5, "Unexpected number of CVEs returned"

@pytest.mark.asyncio
async def test_epss_cves_above_epss_threshold():
    """Test fetching CVEs with EPSS scores greater than a threshold."""
    async with FirstEpssApiClient() as client:
        response = await client.get_cves(epss_gt=0.95, limit=5)
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 5, "Unexpected number of CVEs returned"

@pytest.mark.asyncio
async def test_epss_combined_filters_advanced():
    """Test combined filters with date, EPSS threshold, and ordering."""
    async with FirstEpssApiClient() as client:
        response = await client.get_cves(
            date="2022-03-05", epss_gt=0.95, order=FirstEpssOrderOption.EPSS_DESC, limit=5
        )
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 5, "Unexpected number of CVEs returned"
        for item in response.data:
            assert float(item.epss) > 0.95, f"EPSS score below threshold: {item.epss}"

@pytest.mark.asyncio
async def test_epss_cves_above_percentile_threshold():
    """Test fetching CVEs with percentiles greater than a threshold."""
    async with FirstEpssApiClient() as client:
        response = await client.get_cves(percentile_gt=0.95, limit=5)
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 5, "Unexpected number of CVEs returned"
        for item in response.data:
            assert float(item.percentile) > 0.95, f"Percentile below threshold: {item.percentile}"

@pytest.mark.asyncio
async def test_epss_no_results():
    """Test fetching EPSS scores for a non-existent CVE."""
    async with FirstEpssApiClient() as client:
        response = await client.get_scores_json(["CVE-9999-9999"])
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 0, "Expected no results for a non-existent CVE"

@pytest.mark.asyncio
async def test_epss_most_recent_cves():
    """Test fetching the first 100 most recent CVEs."""
    async with FirstEpssApiClient() as client:
        response = await client.get_recent_cves(limit=100)
        assert response.status == "OK", "API status is not OK"
        assert len(response.data) == 100, "Unexpected number of CVEs returned"

@pytest.mark.asyncio
async def test_epss_pagination():
    """Test pagination with different offsets."""
    async with FirstEpssApiClient() as client:
        first_page = await client.get_recent_cves(offset=0, limit=10)
        second_page = await client.get_recent_cves(offset=10, limit=10)
        assert first_page.status == "OK" and second_page.status == "OK", "API status is not OK"
        assert len(first_page.data) == 10 and len(second_page.data) == 10, "Unexpected page size"
        assert first_page.data != second_page.data, "Pagination not working correctly"

@pytest.mark.asyncio
async def test_epss_full_csv_download():
    """Test downloading and decompressing the full CSV for a specific date."""
    async with FirstEpssApiClient() as client:
        csv_data = await client.download_and_decompress_full_csv_for_date("2022-03-05")
        lines = csv_data.splitlines()
        header_line = next(line for line in lines if line.startswith("cve"))
        assert header_line == "cve,epss,percentile", "CSV header missing or incorrect"
