"""Integration check for observable security metrics."""

import os

import pytest
import requests

BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
pytestmark = pytest.mark.integration


def test_security_metrics_are_available():
    response = requests.get(f"{BASE_URL}/system/security-metrics", timeout=10)

    response.raise_for_status()
    overview = response.json()["overview"]
    assert "total_requests" in overview
    assert "block_rate_percentage" in overview
