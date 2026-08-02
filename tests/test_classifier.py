"""Classification engine tests."""
import json

import classifier
import collectors
import metadata
import report

HOME = "home-tenant-guid"


def _app(**kw):
    base = dict(match_signal="generic", vendor="Unknown AI", verified_publisher=False,
                owner_tenant="ext-1", third_party=True, first_party_microsoft=False,
                consent_type="Principal", user_count=5, has_app_only_access=False,
                lifecycle={"status": "Discovered"}, business_context={}, ownership={})
    base.update(kw)
    return base


# --- Acceptance criteria --------------------------------------------------------

def test_known_app_id_classified():
    """Criterion: a known application can be classified via App ID."""
    app = _app(match_signal="app_id", vendor="OpenAI (ChatGPT)", verified_publisher=True,
               owner_tenant="ext-openai", consent_type="AllPrincipals", user_count=340)
    c = classifier.classify(app, HOME)
    assert c["category"] == "Third-Party Shadow AI"
    assert c["ownership"] == "External"
    assert c["confidence"] >= 90
    assert any("App ID" in r for r in c["reasons"])          # reason is visible
    assert c["manual_override"] is False


def test_unknown_not_safe_or_approved():
    """Criterion: Unknown status is never treated as safe or approved."""
    c = classifier.classify(_app(match_signal="generic"), HOME)
    assert c["category"] == "Unknown AI"
    assert c["category"] not in ("Approved Enterprise AI",)
    assert c["confidence"] <= 40
    assert any("review" in r.lower() for r in c["reasons"])


def test_manual_override_wins_and_preserved():
    """Criterion: manual override is preserved (via the metadata store)."""
    store = {}
    metadata.set_metadata(store, "app-1",
                          {"classification": {"category": "Approved Enterprise AI"}})
    # new scan — fresh finding, no override
    findings = [_app(app_id="app-1", match_signal="app_id", vendor="OpenAI (ChatGPT)")]
    findings[0]["app_id"] = "app-1"
    metadata.merge(findings, store)                 # restores the override
    classifier.classify_all(findings, HOME)
    c = findings[0]["classification"]
    assert c["category"] == "Approved Enterprise AI"
    assert c["manual_override"] is True
    assert c["confidence"] == 100


def test_microsoft_first_party_classified_and_visible():
    """Criterion: Microsoft applications are visible in inventory + classified."""
    app = _app(first_party_microsoft=True, third_party=False, match_signal="generic",
               vendor="Security Copilot", owner_tenant="f8cdef31-a31e-4b4a-93e4-5f571e91255a")
    c = classifier.classify(app, HOME)
    assert c["category"] == "Microsoft First-Party AI"


def test_ownership_internal_external_unknown():
    assert classifier.classify(_app(owner_tenant=HOME, match_signal="app_id"), HOME)["ownership"] == "Internal"
    assert classifier.classify(_app(owner_tenant="ext-9"), HOME)["ownership"] == "External"
    assert classifier.classify(_app(owner_tenant=None), HOME)["ownership"] == "Unknown"


def test_personal_usage_pattern():
    app = _app(match_signal="app_id", vendor="OpenAI (ChatGPT)", consent_type="Principal",
               user_count=1, owner_tenant="ext-openai")
    assert classifier.classify(app, HOME)["category"] == "Personal AI Usage"


def test_lifecycle_drives_enterprise_category():
    assert classifier.classify(_app(match_signal="app_id", lifecycle={"status": "Approved"}),
                               HOME)["category"] == "Approved Enterprise AI"
    assert classifier.classify(_app(match_signal="app_id", lifecycle={"status": "Blocked"}),
                               HOME)["category"] == "Unapproved Enterprise AI"
    assert classifier.classify(_app(match_signal="app_id", lifecycle={"status": "Retired"}),
                               HOME)["category"] == "Retired AI"


def test_business_ownership_makes_unapproved_enterprise():
    app = _app(match_signal="app_id", business_context={"business_unit": "Finance"})
    assert classifier.classify(app, HOME)["category"] == "Unapproved Enterprise AI"


# --- Catalog / signal --------------------------------------------------------

def test_match_vendor_app_id_strongest():
    sp = {"appId": "e0476654-c1d5-430b-ab80-70cbd947616a", "displayName": "Random Name"}
    name, conf, signal = collectors._match_vendor(sp)
    assert name == "OpenAI (ChatGPT)" and signal == "app_id"


def test_match_vendor_by_homepage():
    # No hint in the name; matches via homepage (pattern/domain)
    sp = {"appId": "x", "displayName": "Some Tool", "homepage": "https://app.perplexity.ai"}
    name, conf, signal = collectors._match_vendor(sp)
    assert name == "Perplexity" and signal in ("pattern", "domain")


# --- Dashboard ---------------------------------------------------------------

def test_dashboard_classification_section_and_ms_visible():
    def full(**kw):
        base = dict(vendor="X", third_party=True, verified_publisher=True, scopes=["user.read"],
                    consent_type="Principal", user_count=3, risk_score=20, risk_level="Low",
                    reasons=["r"], remediation=["m"], delegated_permissions=[],
                    application_permissions=[], has_app_only_access=False, usage=None,
                    ownership={"application_owners": [], "service_principal_owners": []},
                    business_context={}, lifecycle={"status": "Discovered"},
                    technical_inventory={}, notes="", history=[])
        base.update(kw)
        return base

    apps = [
        full(app_id="a1", display_name="ChatGPT", first_party_microsoft=False,
             classification={"category": "Third-Party Shadow AI", "ownership": "External",
                             "confidence": 95, "reasons": ["Known App ID"], "manual_override": False}),
        full(app_id="a2", display_name="Security Copilot", first_party_microsoft=True, risk_score=0,
             classification={"category": "Microsoft First-Party AI", "ownership": "External",
                             "confidence": 90, "reasons": ["Microsoft first-party"], "manual_override": False}),
        full(app_id="a3", display_name="MysteryAI", first_party_microsoft=False,
             classification={"category": "Unknown AI", "ownership": "External",
                             "confidence": 40, "reasons": ["needs review"], "manual_override": False}),
    ]
    doc = report.html_string(apps, "t")
    assert "Classification" in doc
    assert "Unknown AI — review queue" in doc
    assert "MysteryAI" in doc                              # in the unknown queue
    assert "Security Copilot" in doc                       # visible in MS inventory
    assert 'data-cat="Microsoft First-Party AI"' in doc    # MS finding row
    assert 'data-group="cat"' in doc                       # classification filter
    assert "Known App ID" in doc                            # classification reason is shown


# --- catalog loading --------------------------------------------------------
def test_shipped_catalog_covers_the_major_vendors():
    import config
    names = " ".join(v["name"] for v in config.AI_VENDORS).lower()
    for vendor in ("openai", "anthropic", "gemini", "perplexity", "glean",
                   "otter", "cursor", "midjourney", "copilot"):
        assert vendor in names, vendor
    assert len(config.AI_VENDORS) >= 60


def test_every_catalog_entry_has_a_usable_signal():
    import config
    for v in config.AI_VENDORS:
        assert v.get("name")
        assert v.get("app_ids") or v.get("patterns") or v.get("domains"), v["name"]
        for pat in v.get("patterns", []):
            assert pat == pat.lower(), f"{v['name']}: patterns are matched lowercase"
        for dom in v.get("domains", []):
            assert dom == dom.lower(), f"{v['name']}: domains are matched lowercase"


def test_catalog_can_be_overridden_without_a_redeploy(tmp_path, monkeypatch):
    import config
    custom = tmp_path / "mine.json"
    custom.write_text(json.dumps({
        "vendors": [{"name": "Acme Internal AI", "app_ids": [], "patterns": ["acme-ai"],
                     "domains": ["acme.example"]}],
        "generic_hints": ["acme"],
    }), encoding="utf-8")
    monkeypatch.setenv("AISPM_CATALOG_PATH", str(custom))
    loaded = config.load_catalog()
    assert [v["name"] for v in loaded["vendors"]] == ["Acme Internal AI"]


def test_a_broken_override_falls_back_instead_of_finding_nothing(tmp_path, monkeypatch):
    """An empty catalog would make a healthy tenant look clean — the worst failure mode."""
    import config
    for content in ("{ not json", json.dumps({"vendors": []})):
        bad = tmp_path / "bad.json"
        bad.write_text(content, encoding="utf-8")
        monkeypatch.setenv("AISPM_CATALOG_PATH", str(bad))
        assert len(config.load_catalog()["vendors"]) >= 60

    monkeypatch.setenv("AISPM_CATALOG_PATH", str(tmp_path / "nope.json"))
    assert len(config.load_catalog()["vendors"]) >= 60
