"""End-to-end API checks for the Docker Compose stack."""

import os

import pytest
import requests

BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def auth_headers():
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "secret123"},
        timeout=10,
    )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_health():
    response = requests.get(f"{BASE_URL}/system/health", timeout=10)

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_models():
    response = requests.get(f"{BASE_URL}/llm/models", timeout=30)

    response.raise_for_status()
    assert "groq-qwen-primary" in str(response.json())


def test_generate_with_primary_model(auth_headers):
    response = requests.post(
        f"{BASE_URL}/llm/generate",
        headers=auth_headers,
        json={
            "prompt": "Reply with exactly: LLMOps E2E OK",
            "model": "groq-qwen-primary",
            "temperature": 0,
            "max_tokens": 20,
        },
        timeout=90,
    )

    response.raise_for_status()
    payload = response.json()
    assert payload["response"]
    assert payload["model"]
