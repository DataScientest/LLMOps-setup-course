"""Unit tests for the Qdrant-backed exact cache."""

import time

import pytest
from qdrant_client import QdrantClient

from cache.exact_cache import ExactCache


@pytest.fixture
def cache_service():
    return ExactCache(client=QdrantClient(":memory:"), ttl_seconds=60)


def test_cache_key_generation_is_stable(cache_service):
    key1 = cache_service._hash_prompt(
        "Test prompt", "test-model", temperature=0.7, max_tokens=100
    )
    key2 = cache_service._hash_prompt(
        "Test prompt", "test-model", max_tokens=100, temperature=0.7
    )

    assert key1 == key2


def test_cache_store_and_retrieve(cache_service):
    response = {"response": "42", "total_tokens": 1, "cost": 0.0}

    assert cache_service.set("Meaning of life?", "test-model", response) is True
    assert cache_service.get("Meaning of life?", "test-model") == response


def test_cache_miss(cache_service):
    assert cache_service.get("Not cached", "test-model") is None


def test_expired_entry_is_removed():
    cache = ExactCache(client=QdrantClient(":memory:"), ttl_seconds=0)
    response = {"response": "stale", "total_tokens": 1, "cost": 0.0}

    assert cache.set("Prompt", "test-model", response) is True
    time.sleep(0.01)

    assert cache.get("Prompt", "test-model") is None
