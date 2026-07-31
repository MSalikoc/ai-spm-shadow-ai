"""
Connector registry / resilient runner.

Runs all connectors in sequence; if one fails (safe_run never raises) the others
still proceed. The raw entities are then correlated and returned as a unified asset
list + per-source coverage/health.
"""
from . import correlation


def run(collectors, since=None) -> dict:
    all_entities = []
    coverage, health = {}, {}
    for c in collectors:
        entities = c.safe_run(since)          # resilient: exceptions are swallowed
        all_entities.extend(entities)
        coverage[c.name] = c.get_coverage()
        health[c.name] = c.get_health()
    merged = correlation.correlate(all_entities)
    return {
        "assets": merged,
        "coverage": coverage,
        "health": health,
        "counts": {"raw": len(all_entities), "merged": len(merged)},
    }
