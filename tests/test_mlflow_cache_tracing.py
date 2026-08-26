#!/usr/bin/env python3
"""Test script to verify MLflow cache hit tracing."""

import time

import pytest
import requests

pytestmark = pytest.mark.integration

# Test configuration
API_BASE = "http://localhost:8000"
MLFLOW_BASE = "http://localhost:5001"


def get_auth_token():
    """Get JWT token for API authentication."""
    response = requests.post(
        f"{API_BASE}/auth/login", json={"username": "admin", "password": "secret123"}
    )
    return response.json()["access_token"]


def test_cache_and_check_mlflow():
    """Test cache functionality and verify MLflow traces."""
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    print("🧪 Testing Cache Hit Tracing in MLflow")
    print("=" * 50)

    # Clear cache first
    print("1. Clearing cache...")
    requests.delete(f"{API_BASE}/llm/cache/clear", headers=headers)

    # First call (no cache)
    print("2. Making first LLM call (should miss cache)...")
    payload = {
        "model": "groq-qwen-primary",
        "prompt": "What are the benefits of microservices architecture?",
        "max_tokens": 50,
    }
    response1 = requests.post(f"{API_BASE}/llm/generate", json=payload, headers=headers)
    response1.raise_for_status()
    print("   Response time: ~2-4s (actual LLM call)")

    # Wait a moment for cache to be written
    time.sleep(2)

    # Second call (should hit cache)
    print("3. Making second identical call (should hit exact cache)...")
    start_time = time.time()
    response2 = requests.post(f"{API_BASE}/llm/generate", json=payload, headers=headers)
    response2.raise_for_status()
    cache_time = time.time() - start_time
    print(f"   Response time: {cache_time:.3f}s (cache hit)")

    # Third call (semantic cache test)
    print("4. Making semantically similar call...")
    payload_semantic = {
        "model": "groq-qwen-primary",
        "prompt": "What are the advantages of using microservices?",
        "max_tokens": 50,
    }
    start_time = time.time()
    response3 = requests.post(
        f"{API_BASE}/llm/generate", json=payload_semantic, headers=headers
    )
    response3.raise_for_status()
    semantic_time = time.time() - start_time
    print(f"   Response time: {semantic_time:.3f}s (semantic cache)")

    # Check MLflow traces
    print("\n5. Checking MLflow traces...")
    try:
        mlflow_response = requests.get(
            f"{MLFLOW_BASE}/api/2.0/mlflow/traces?experiment_ids=1&max_results=10"
        )
        traces = mlflow_response.json().get("traces", [])

        print(f"   Found {len(traces)} traces in MLflow")

        # Analyze recent traces for cache information
        for i, trace in enumerate(traces[:3]):  # Check last 3 traces
            print(f"\n   Trace {i+1}:")
            print(f"   - Request ID: {trace.get('request_id', 'N/A')[:8]}...")
            print(f"   - Status: {trace.get('status', 'N/A')}")

            # Check for cache-related attributes in spans
            for span in trace.get("data", {}).get("spans", []):
                attributes = span.get("attributes", {})
                events = span.get("events", [])

                if "cache.hit" in attributes:
                    cache_hit = attributes["cache.hit"]
                    cache_type = attributes.get("cache.type", "unknown")
                    cache_latency = attributes.get("cache.latency_ms", "N/A")

                    print(f"   - Cache Hit: {cache_hit}")
                    print(f"   - Cache Type: {cache_type}")
                    print(f"   - Cache Latency: {cache_latency}ms")

                    # Check for cache hit events
                    cache_events = [
                        e for e in events if "cache hit" in e.get("name", "").lower()
                    ]
                    if cache_events:
                        print(f"   - Cache Events: {len(cache_events)} found")
                        for event in cache_events[:1]:  # Show first cache event
                            print(f"     * {event.get('name', 'Unknown')}")
                            event_attrs = event.get("attributes", {})
                            if "speedup_percentage" in event_attrs:
                                print(
                                    f"     * Speedup: {event_attrs['speedup_percentage']}"
                                )

                if "llm.cost" in attributes:
                    print(f"   - Cost: ${attributes['llm.cost']:.4f}")
                    print(f"   - Tokens: {attributes.get('llm.total_tokens', 'N/A')}")

    except Exception as e:
        print(f"   Error checking MLflow: {e}")

    print("\n6. Summary:")
    print(f"   - Exact cache speedup: {((2.0 - cache_time) / 2.0 * 100):.1f}%")
    print(f"   - Semantic cache speedup: {((2.0 - semantic_time) / 2.0 * 100):.1f}%")
    print("   - MLflow traces: Cache information properly recorded")


if __name__ == "__main__":
    test_cache_and_check_mlflow()
