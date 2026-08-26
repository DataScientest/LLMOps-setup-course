"""Integration checks for JWT authentication."""

import os

import pytest
import requests

BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
pytestmark = pytest.mark.integration


@pytest.fixture
def token():
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "secret123"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def test_login():
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "secret123"},
        timeout=10,
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


def test_invalid_login():
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
        timeout=10,
    )

    assert response.status_code == 401


def test_secured_endpoint_without_token():
    response = requests.post(
        f"{BASE_URL}/llm/generate",
        json={"model": "groq-qwen-primary", "prompt": "Hello"},
        timeout=10,
    )

    assert response.status_code in {401, 403}


def test_user_info(token):
    response = requests.get(
        f"{BASE_URL}/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    response.raise_for_status()
    assert response.json()["username"] == "admin"
