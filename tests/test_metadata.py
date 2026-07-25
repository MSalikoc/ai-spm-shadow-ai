"""Business ownership + lifecycle metadata testleri."""
from datetime import datetime, timedelta, timezone

import collectors
import metadata
import report

NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)


def test_manual_metadata_survives_rescan():
    """Kriter 5: manuel metadata sonraki tarama merge'inde kaybolmuyor."""
    store = {}
    metadata.set_metadata(store, "app-1", {
        "ownership": {"business_owner": "Finance Applications Team"},
        "business_context": {"business_unit": "Finance", "subsidiary": "Contoso Europe"},
        "lifecycle": {"status": "Under Review", "next_review_date": "2026-10-01"},
    }, now=NOW)

    # "yeni tarama" — Graph'tan taze bulgular (metadata YOK)
    findings = [{"app_id": "app-1", "display_name": "InvoiceAI"},
                {"app_id": "app-2", "display_name": "OtherAI"}]
    metadata.merge(findings, store)

    assert findings[0]["ownership"]["business_owner"] == "Finance Applications Team"
    assert findings[0]["business_context"]["business_unit"] == "Finance"
    assert findings[0]["lifecycle"]["status"] == "Under Review"
    # Metadata girilmemiş app default alır
    assert findings[1]["lifecycle"]["status"] == "Discovered"


def test_technical_and_business_owner_separated():
    """Kriter: teknik ve business owner ayrımı."""
    store = {}
    metadata.set_metadata(store, "app-1",
                          {"ownership": {"business_owner": "BU Team"}}, now=NOW)
    findings = [{"app_id": "app-1",
                 "ownership": {"application_owners": [],
                               "service_principal_owners": [{"id": "u1", "name": "Eng Admin"}]}}]
    metadata.merge(findings, store)
    own = findings[0]["ownership"]
    assert own["service_principal_owners"][0]["name"] == "Eng Admin"  # teknik
    assert own["business_owner"] == "BU Team"                          # business
    assert own["application_owners"] == []


def test_lifecycle_history_recorded():
    """Kriter 9: lifecycle ve review değişiklikleri history'de."""
    store = {}
    metadata.set_metadata(store, "app-1", {"lifecycle": {"status": "Under Review"}}, now=NOW)
    later = NOW + timedelta(days=5)
    metadata.set_metadata(store, "app-1",
                          {"lifecycle": {"status": "Approved", "next_review_date": "2027-01-01"}},
                          now=later)
    hist = store["app-1"]["history"]
    statuses = [(h["field"], h["from"], h["to"]) for h in hist]
    assert ("status", "Discovered", "Under Review") in statuses
    assert ("status", "Under Review", "Approved") in statuses
    assert any(h["field"] == "next_review_date" for h in hist)


def test_invalid_lifecycle_status_ignored():
    store = {}
    metadata.set_metadata(store, "app-1", {"lifecycle": {"status": "Bogus"}}, now=NOW)
    assert store["app-1"]["lifecycle"]["status"] == "Discovered"  # geçersiz değer yok sayıldı


def test_upcoming_reviews():
    """Kriter: review tarihi yaklaşan uygulamalar listelenebiliyor."""
    findings = [
        {"app_id": "a", "display_name": "Due", "lifecycle": {"next_review_date": "2026-08-10"}},
        {"app_id": "b", "display_name": "Overdue", "lifecycle": {"next_review_date": "2026-07-01"}},
        {"app_id": "c", "display_name": "Far", "lifecycle": {"next_review_date": "2027-01-01"}},
        {"app_id": "d", "display_name": "None", "lifecycle": {"next_review_date": None}},
    ]
    due = metadata.upcoming_reviews(findings, within_days=30, now=NOW)
    names = [f["display_name"] for f in due]
    assert "Overdue" in names and "Due" in names
    assert "Far" not in names and "None" not in names
    assert names[0] == "Overdue"  # en geçmiş önce


def test_ownership_collector_no_synthesis():
    """Kriter 2: owner yoksa boş; otomatik kişi üretilmez."""
    class G:
        def get(self, path, params=None):
            return {"accountEnabled": True, "publisherName": "OpenAI",
                    "keyCredentials": [{"endDateTime": "2026-12-01T00:00:00Z"}],
                    "passwordCredentials": []}

        def get_all(self, path, params=None, max_items=None):
            return []  # owner yok
    apps = [{"sp_id": "sp1", "publisher": "OpenAI"}]
    collectors.enrich_with_ownership(G(), apps)
    assert apps[0]["ownership"]["service_principal_owners"] == []   # boş, uydurma yok
    assert apps[0]["technical_inventory"]["credential_count"] == 1
    assert apps[0]["technical_inventory"]["credential_next_expiry"] == "2026-12-01T00:00:00Z"


def test_dashboard_shows_governance_and_bu_filter():
    apps = [{"display_name": "InvoiceAI", "vendor": "X", "first_party_microsoft": False,
             "third_party": True, "verified_publisher": True, "scopes": ["user.read"],
             "consent_type": "Principal", "user_count": 5, "risk_score": 30, "risk_level": "Orta",
             "reasons": ["r"], "remediation": ["m"], "app_id": "app-1",
             "delegated_permissions": [], "application_permissions": [], "has_app_only_access": False,
             "usage": None,
             "ownership": {"application_owners": [], "service_principal_owners": [],
                           "business_owner": "Finance Team", "technical_owner": "", "sponsor": ""},
             "business_context": {"business_unit": "Finance", "subsidiary": "Contoso Europe",
                                  "purpose": "Invoice analysis", "criticality": "High",
                                  "environment": "Production", "process": ""},
             "lifecycle": {"status": "Under Review", "next_review_date": "2026-08-10"},
             "technical_inventory": {"credential_count": 0}, "notes": "", "history": []}]
    doc = report.html_string(apps, "t")
    assert "Yönetişim" in doc                          # governance bölümü
    assert 'data-group="bu"' in doc                    # BU filtresi
    assert '<option value="Finance">' in doc           # BU seçeneği
    assert "Under Review" in doc                       # lifecycle gösteriliyor
    assert 'data-bu="Finance"' in doc                  # satır BU etiketi
    assert "Metadata düzenle" in doc                   # dashboard editör
    assert "Yaklaşan / geçmiş review" in doc           # upcoming reviews
