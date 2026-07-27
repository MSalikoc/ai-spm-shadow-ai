"""
Smoke testleri — deployment öncesi import ve temel davranış hatalarını yakalar.

En kritik test `test_module_imports`: `function_app` dahil tüm modüllerin import
edilebildiğini doğrular. Bu, `notify.py` gibi bir modülün deployment paketinden
eksik kalması sonucu oluşan `ModuleNotFoundError` sınıfı hataları CI'da yakalar.
"""
import importlib

import pytest

MODULES = [
    "config", "auth", "graph_client", "collectors", "scoring",
    "pipeline", "report", "storage", "notify", "main", "function_app",
    "connectors_report", "connectors_drift",
]


@pytest.mark.parametrize("mod", MODULES)
def test_module_imports(mod):
    importlib.import_module(mod)


def test_function_app_registers():
    import function_app
    assert function_app.app is not None


def test_scoring_ranks_by_risk():
    from scoring import score_all
    risky = {"scopes": ["files.readwrite.all", "offline_access"],
             "consent_type": "AllPrincipals", "user_count": 50,
             "verified_publisher": False, "third_party": True, "confidence": "high"}
    benign = {"scopes": ["user.read"], "consent_type": "Principal", "user_count": 1,
              "verified_publisher": True, "third_party": True, "confidence": "high"}
    scored = score_all([dict(risky), dict(benign)])
    assert scored[0]["risk_score"] >= scored[1]["risk_score"]
    assert scored[0]["risk_level"] in ("Kritik", "Yüksek", "Orta", "Düşük")
    assert scored[0]["reasons"]


def test_report_html_contains_findings():
    from report import html_string
    apps = [{"display_name": "ChatGPT", "vendor": "OpenAI", "first_party_microsoft": False,
             "third_party": True, "verified_publisher": True, "scopes": ["files.read.all"],
             "consent_type": "AllPrincipals", "user_count": 0, "risk_score": 81,
             "risk_level": "Kritik", "reasons": ["x"], "remediation": ["y"]}]
    doc = html_string(apps, "tenant-1")
    assert "AI-SPM" in doc and "ChatGPT" in doc and "<!doctype html>" in doc.lower()


def test_report_separates_microsoft_first_party():
    from report import html_string
    apps = [
        {"display_name": "ChatGPT", "vendor": "OpenAI", "first_party_microsoft": False,
         "third_party": True, "verified_publisher": True, "scopes": ["files.read.all"],
         "consent_type": "AllPrincipals", "user_count": 0, "risk_score": 81,
         "risk_level": "Kritik", "reasons": ["x"], "remediation": ["y"]},
        {"display_name": "Security Copilot", "vendor": "MS", "first_party_microsoft": True,
         "third_party": False, "verified_publisher": True, "scopes": [],
         "consent_type": None, "user_count": 0, "risk_score": 0,
         "risk_level": "Düşük", "reasons": [], "remediation": []},
    ]
    doc = html_string(apps, "t")
    assert "Microsoft first-party" in doc  # governed section rendered


def test_digest_excludes_microsoft_first_party():
    from notify import _digest_html
    apps = [
        {"display_name": "ChatGPT", "vendor": "OpenAI", "first_party_microsoft": False,
         "risk_score": 81, "risk_level": "Kritik", "reasons": ["x"]},
        {"display_name": "Security Copilot", "first_party_microsoft": True,
         "risk_score": 0, "risk_level": "Düşük", "reasons": []},
    ]
    body = _digest_html(apps, "t", None)
    assert "ChatGPT" in body
    assert "Security Copilot" not in body


def test_pipeline_summary_shape():
    from pipeline import summary
    apps = [{"risk_level": "Kritik", "display_name": "A", "vendor": "v", "risk_score": 80}]
    s = summary(apps)
    assert s["total"] == 1 and s["critical"] == 1 and "top" in s
