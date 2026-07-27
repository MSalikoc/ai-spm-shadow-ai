"""
Connector registry / dayanıklı çalıştırıcı.

Tüm connector'ları sırayla çalıştırır; biri başarısız olsa bile (safe_run asla
fırlatmaz) diğerleri devam eder. Sonuçta ham entity'ler korele edilip birleşik
asset listesi + kaynak bazlı coverage/health döner.
"""
from . import correlation


def run(collectors, since=None) -> dict:
    all_entities = []
    coverage, health = {}, {}
    for c in collectors:
        entities = c.safe_run(since)          # dayanıklı: exception yutulur
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
