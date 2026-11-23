"""The Grafana dashboard must be fed by real /llm/generate traffic."""

from prometheus_client import REGISTRY

from middleware.metrics import record_generation


def value(name, labels=None):
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


def test_record_generation_feeds_dashboard_metrics():
    misses = value("llmops_cache_misses_total")
    exact = value("llmops_cache_hits_total", {"cache_type": "exact"})

    record_generation(cache_type=None, duration_s=1.2, cost=0.001, model="gpt-oss-120b")
    record_generation(cache_type="exact", duration_s=0.01)
    record_generation(cache_type="semantic", duration_s=0.05, similarity=0.9)

    assert value("llmops_cache_misses_total") == misses + 1
    assert value("llmops_cache_hits_total", {"cache_type": "exact"}) == exact + 1
    assert value("llmops_llm_cost_usd_total", {"model": "gpt-oss-120b"}) >= 0.001
    assert 0 < value("llmops_cache_hit_ratio", {"cache_type": "exact"}) < 1
    assert value("llmops_cache_similarity_quality_total", {"quality": "good"}) >= 1
    assert value("llmops_cache_performance_savings_ms", {"cache_type": "exact"}) > 0


def test_dashboard_only_queries_exported_metrics():
    import json
    import re
    from pathlib import Path

    import middleware.metrics  # noqa: F401  (registers the metrics)
    import routers.monitoring  # noqa: F401

    exported = set()
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            exported.add(sample.name)
        exported.add(metric.name)
        exported.add(metric.name + "_total")

    dashboard = Path(__file__).parents[1] / "monitoring/grafana/dashboards/main-dashboard.json"
    exprs = [t["expr"] for p in json.loads(dashboard.read_text())["panels"] for t in p.get("targets", [])]
    used = {m for e in exprs for m in re.findall(r"\b(llmops_[a-z_]+)", e)}
    missing = {m for m in used if m not in exported and m.rsplit("_", 1)[0] not in exported}
    assert not missing, f"Dashboard queries metrics the API never exports: {missing}"
