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

    cache_key = cache._hash_prompt("capital", "groq-primary")
    uuid.UUID(cache_key)

    assert cache.set("capital", "groq-primary", response)
    assert cache.get("capital", "groq-primary") == response


def test_cache_key_includes_parameters():
    cache = make_cache()

    first = cache._hash_prompt("capital", "groq-primary", temperature=0)
    second = cache._hash_prompt("capital", "groq-primary", temperature=1)

    assert first != second


def test_cache_recreates_collection_with_wrong_vector_size():
    # Older init scripts created exact_cache with 384 dimensions, which made
    # every write fail with "Vector dimension error: expected dim: 384, got 1".
    from qdrant_client.models import Distance, VectorParams

    client = QdrantClient(":memory:")
    client.create_collection(
        collection_name="exact_cache",
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )
    ExactCache(client=client)

    # The in-memory client does not enforce dimensions, so check the schema.
    vectors = client.get_collection("exact_cache").config.params.vectors
    assert vectors.size == 1


def test_cache_stats_counts_entries():
    cache = make_cache()
    cache.set("capital", "groq-primary", {"response": "Paris"})

    assert cache.get_cache_stats()["exact_cache"]["entries"] == 1
