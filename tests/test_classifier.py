"""Classification engine testleri."""
import classifier
import collectors
import metadata
import report

HOME = "home-tenant-guid"


def _app(**kw):
    base = dict(match_signal="generic", vendor="Bilinmeyen AI", verified_publisher=False,
                owner_tenant="ext-1", third_party=True, first_party_microsoft=False,
                consent_type="Principal", user_count=5, has_app_only_access=False,
                lifecycle={"status": "Discovered"}, business_context={}, ownership={})
    base.update(kw)
    return base


# --- Kabul kriterleri --------------------------------------------------------

def test_known_app_id_classified():
    """Kriter: App ID üzerinden bilinen uygulama sınıflandırılabiliyor."""
    app = _app(match_signal="app_id", vendor="OpenAI (ChatGPT)", verified_publisher=True,
               owner_tenant="ext-openai", consent_type="AllPrincipals", user_count=340)
    c = classifier.classify(app, HOME)
    assert c["category"] == "Third-Party Shadow AI"
    assert c["ownership"] == "External"
    assert c["confidence"] >= 90
    assert any("App ID" in r for r in c["reasons"])          # reason görüntülenebiliyor
    assert c["manual_override"] is False


def test_unknown_not_safe_or_approved():
    """Kriter: Unknown durum güvenli veya approved kabul edilmiyor."""
    c = classifier.classify(_app(match_signal="generic"), HOME)
    assert c["category"] == "Unknown AI"
    assert c["category"] not in ("Approved Enterprise AI",)
    assert c["confidence"] <= 40
    assert any("inceleme" in r.lower() for r in c["reasons"])


def test_manual_override_wins_and_preserved():
    """Kriter: manuel override korunuyor (metadata deposu üzerinden)."""
    store = {}
    metadata.set_metadata(store, "app-1",
                          {"classification": {"category": "Approved Enterprise AI"}})
    # yeni tarama — taze bulgu, override YOK
    findings = [_app(app_id="app-1", match_signal="app_id", vendor="OpenAI (ChatGPT)")]
    findings[0]["app_id"] = "app-1"
    metadata.merge(findings, store)                 # override'ı geri yükler
    classifier.classify_all(findings, HOME)
    c = findings[0]["classification"]
    assert c["category"] == "Approved Enterprise AI"
    assert c["manual_override"] is True
    assert c["confidence"] == 100


def test_microsoft_first_party_classified_and_visible():
    """Kriter: Microsoft uygulamaları envanterde görülebiliyor + sınıflanıyor."""
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


# --- Katalog / sinyal --------------------------------------------------------

def test_match_vendor_app_id_strongest():
    sp = {"appId": "e0476654-c1d5-430b-ab80-70cbd947616a", "displayName": "Random Name"}
    name, conf, signal = collectors._match_vendor(sp)
    assert name == "OpenAI (ChatGPT)" and signal == "app_id"


def test_match_vendor_by_homepage():
    # İsimde ipucu yok; homepage'den (pattern/domain) eşleşir
    sp = {"appId": "x", "displayName": "Some Tool", "homepage": "https://app.perplexity.ai"}
    name, conf, signal = collectors._match_vendor(sp)
    assert name == "Perplexity" and signal in ("pattern", "domain")


# --- Dashboard ---------------------------------------------------------------

def test_dashboard_classification_section_and_ms_visible():
    def full(**kw):
        base = dict(vendor="X", third_party=True, verified_publisher=True, scopes=["user.read"],
                    consent_type="Principal", user_count=3, risk_score=20, risk_level="Düşük",
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
                             "confidence": 95, "reasons": ["Bilinen App ID"], "manual_override": False}),
        full(app_id="a2", display_name="Security Copilot", first_party_microsoft=True, risk_score=0,
             classification={"category": "Microsoft First-Party AI", "ownership": "External",
                             "confidence": 90, "reasons": ["Microsoft first-party"], "manual_override": False}),
        full(app_id="a3", display_name="MysteryAI", first_party_microsoft=False,
             classification={"category": "Unknown AI", "ownership": "External",
                             "confidence": 40, "reasons": ["inceleme gerekli"], "manual_override": False}),
    ]
    doc = report.html_string(apps, "t")
    assert "Sınıflandırma" in doc
    assert "Unknown AI — inceleme kuyruğu" in doc
    assert "MysteryAI" in doc                              # unknown kuyruğunda
    assert "Security Copilot" in doc                       # MS envanterde görünür
    assert 'data-cat="Microsoft First-Party AI"' in doc    # MS finding satırı
    assert 'data-group="cat"' in doc                       # classification filtresi
    assert "Bilinen App ID" in doc                         # classification reason gösteriliyor
