import uuid

from cache.exact_cache import ExactCache
from qdrant_client import QdrantClient


def make_cache(ttl_seconds=1800):
    return ExactCache(
        ttl_seconds=ttl_seconds,
        client=QdrantClient(":memory:"),
    )


def test_cache_round_trip_uses_qdrant_compatible_id():
    cache = make_cache()
    response = {"response": "Paris", "total_tokens": 3}

    cache_key = cache._hash_prompt("capital", "groq-qwen-primary")
    uuid.UUID(cache_key)

    assert cache.set("capital", "groq-qwen-primary", response)
    assert cache.get("capital", "groq-qwen-primary") == response


def test_cache_key_includes_parameters():
    cache = make_cache()

    first = cache._hash_prompt("capital", "groq-qwen-primary", temperature=0)
    second = cache._hash_prompt("capital", "groq-qwen-primary", temperature=1)

    assert first != second
