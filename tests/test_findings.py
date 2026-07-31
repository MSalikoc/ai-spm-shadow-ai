"""Finding lifecycle / aksiyon takibi testleri."""
import os
from datetime import datetime, timezone

import findings as F
import report

NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)


def _app(app_id, **kw):
    base = dict(app_id=app_id, display_name=app_id, scopes=[], application_permissions=[],
                has_app_only_access=False, consent_type="Principal", verified_publisher=True,
                third_party=True, risk_score=10, first_party_microsoft=False,
                classification={"category": "Third-Party Shadow AI"},
                lifecycle={"status": "Discovered", "next_review_date": None},
                ownership={"business_owner": "Fin Team"}, business_context={},
                usage=None, technical_inventory={})
    base.update(kw)
    return base


def _clean():
    for n in ("findings.json",):
        p = os.path.join("out", n)
        if os.path.exists(p):
            os.remove(p)


def test_deterministic_id_no_duplicate():
    _clean()
    app = _app("app123", ownership={"business_owner": ""})   # owner-missing tetikler
    r1 = F.process([app], now=NOW)
    r2 = F.process([app], now=NOW)   # tekrar tara
    ids1 = sorted(f["finding_id"] for f in r1)
    ids2 = sorted(f["finding_id"] for f in r2)
    assert ids1 == ids2                                # same ID, no duplicate
    assert "finding-app123-owner-missing" in ids1
    # single record (no duplicate produced)
    om = [f for f in r2 if f["finding_id"] == "finding-app123-owner-missing"]
    assert len(om) == 1


def test_last_seen_updates_first_seen_stable():
    _clean()
    app = _app("app1", ownership={"business_owner": ""})
    F.process([app], now=NOW)
    later = datetime(2026, 8, 1, tzinfo=timezone.utc)
    recs = F.process([app], now=later)
    rec = next(f for f in recs if f["rule_key"] == "owner-missing")
    assert rec["first_seen"] == NOW.date().isoformat()
    assert rec["last_seen"] == later.date().isoformat()


def test_resolved_then_reappears_reopens():
    """Criterion 4: a resolved finding found again becomes Reopened."""
    _clean()
    app = _app("app1", ownership={"business_owner": ""})
    F.process([app], now=NOW)
    # owner assigned → finding disappears → auto-Resolved
    fixed = _app("app1", ownership={"business_owner": "Someone"})
    recs = F.process([fixed], now=NOW)
    rec = next(f for f in recs if f["rule_key"] == "owner-missing")
    assert rec["status"] == "Resolved"
    # owner removed again → finding comes back → Reopened
    recs = F.process([app], now=NOW)
    rec = next(f for f in recs if f["rule_key"] == "owner-missing")
    assert rec["status"] == "Reopened"


def test_set_finding_owner_due_status():
    """Criterion: owner and due date can be assigned, status can be changed."""
    store = {"f1": F._default({"finding_id": "f1", "rule_key": "x", "title": "t",
                               "description": "d", "category": "Governance", "severity": "Medium",
                               "priority": "P2", "asset_id": "a", "asset_name": "A",
                               "business_impact": "i", "recommended_action": "act"}, NOW)}
    rec = F.set_finding(store, "f1", {"owner": "Gov Team", "due_date": "2026-08-15",
                                      "status": "Assigned"}, now=NOW)
    assert rec["owner"] == "Gov Team" and rec["due_date"] == "2026-08-15"
    assert rec["status"] == "Assigned"
    assert any(h["field"] == "status" and h["to"] == "Assigned" for h in rec["history"])


def test_overdue_detection():
    """Kriter 10: overdue finding'ler listelenebiliyor."""
    recs = [
        {"finding_id": "f1", "due_date": "2026-07-01", "status": "Open"},      # past
        {"finding_id": "f2", "due_date": "2026-12-01", "status": "Open"},      # gelecek
        {"finding_id": "f3", "due_date": "2026-07-01", "status": "Resolved"},  # closed
        {"finding_id": "f4", "due_date": None, "status": "Open"},
    ]
    od = F.overdue(recs, now=NOW)
    ids = [r["finding_id"] for r in od]
    assert ids == ["f1"]


def test_ticket_adapter_is_interface_only():
    import ticketing
    a = ticketing.get_adapter()
    assert isinstance(a, ticketing.NoopAdapter)
    assert a.create_ticket({}) is None      # no integration
    assert a.get_status("X") is None


def test_dashboard_findings_section_and_overdue():
    recs = [
        {"finding_id": "finding-a-owner-missing", "rule_key": "owner-missing",
         "title": "No business owner assigned", "description": "d", "category": "Governance",
         "severity": "Medium", "priority": "P2", "asset_id": "a", "asset_name": "InvoiceAI",
         "business_impact": "i", "recommended_action": "Assign a business owner.",
         "status": "Open", "owner": "Gov Team", "responsible_team": "", "due_date": "2026-07-01",
         "first_seen": "2026-07-01", "last_seen": "2026-07-25", "resolution_note": "",
         "ticket_reference": "", "closed_date": None, "history": []},
    ]
    doc = report.html_string([], "t", None, recs)
    assert "Findings — manageable records" in doc
    assert "No business owner assigned" in doc
    assert "Overdue findings" in doc and "InvoiceAI" in doc
    assert 'data-finding="finding-a-owner-missing"' in doc   # editor
    assert "finding-a-owner-missing" in doc                  # finding ID is shown


def test_rules_generate_expected_findings():
    apps = [
        _app("a1", ownership={"business_owner": ""}),                          # owner-missing
        _app("a2", consent_type="AllPrincipals", scopes=["files.read.all"]),   # admin-consent-sensitive
        _app("a3", has_app_only_access=True,
             application_permissions=[{"resource": "MG", "permission": "Directory.ReadWrite.All"}]),  # app-only-highpriv
        _app("a4", classification={"category": "Unknown AI"}),                 # unknown-classification
    ]
    gen = F.generate(apps, NOW)
    keys = {v["rule_key"] for v in gen.values()}
    assert {"owner-missing", "admin-consent-sensitive", "app-only-highpriv",
            "unknown-classification"} <= keys
