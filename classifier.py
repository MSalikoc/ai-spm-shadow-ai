"""
Classification engine — AI uygulamalarını governance kategorilerine ayırır.

Sinyaller (güç sırası): manuel override > app_id eşleşmesi > publisher/name/domain >
business metadata / lifecycle > jenerik. Unknown ASLA güvenli/approved sayılmaz.

Kategoriler: config.AI_CATEGORIES. Ownership: Internal / External / Unknown.
Çıktı her app'e `classification` = {category, ownership, confidence, reasons, manual_override}.
"""
from config import MICROSOFT_OWNER_TENANTS


def _ownership(app, home_tenant):
    owner = app.get("owner_tenant")
    if owner is None:
        return "Unknown"
    if owner == home_tenant:
        return "Internal"
    return "External"


def _has_business_ownership(app):
    bc = app.get("business_context") or {}
    own = app.get("ownership") or {}
    return bool(bc.get("business_unit") or own.get("business_owner") or own.get("technical_owner"))


def _personal_pattern(app):
    """Kişisel kullanım: 3. parti, kullanıcı-consent, tek/az kullanıcı, admin onayı yok."""
    return (app.get("third_party")
            and app.get("consent_type") == "Principal"
            and app.get("user_count", 0) <= 2
            and not app.get("has_app_only_access"))


def classify(app, home_tenant):
    ownership = _ownership(app, home_tenant)

    # 1) Manuel override — en güçlü sinyal, korunur (metadata deposundan gelir)
    override = app.get("classification_override") or {}
    if override.get("category"):
        return {
            "category": override["category"],
            "ownership": override.get("ownership") or ownership,
            "confidence": 100,
            "reasons": ["Manuel override (yönetici sınıflandırması)"],
            "manual_override": True,
        }

    reasons = []
    signal = app.get("match_signal")
    vendor = app.get("vendor", "")
    status = (app.get("lifecycle") or {}).get("status")

    # Güven + eşleşme gerekçesi
    if signal == "app_id":
        confidence = 95
        reasons.append(f"Bilinen uygulama App ID ({vendor})")
    elif signal in ("pattern", "domain"):
        confidence = 72
        reasons.append(f"Yayıncı/isim/domain eşleşmesi ({vendor})")
    else:
        confidence = 45
        reasons.append("Jenerik AI eşleşmesi (kesin değil)")

    if app.get("verified_publisher"):
        reasons.append("Doğrulanmış yayıncı")
        confidence = min(100, confidence + 5)
    if ownership == "External":
        reasons.append("Dış yayıncı tenant")
    elif ownership == "Internal":
        reasons.append("İç (home tenant) uygulama")

    # 2) Kategori — öncelik sırası
    if status == "Retired":
        category = "Retired AI"
        reasons.append("Lifecycle: Retired")
    elif app.get("first_party_microsoft"):
        category = "Microsoft First-Party AI"
        reasons.append("Microsoft first-party tenant")
        confidence = max(confidence, 90)
    elif status == "Approved":
        category = "Approved Enterprise AI"
        reasons.append("Lifecycle: Approved")
        confidence = max(confidence, 85)
    elif status in ("Blocked", "Restricted"):
        category = "Unapproved Enterprise AI"
        reasons.append(f"Lifecycle: {status}")
        confidence = max(confidence, 80)
    elif _has_business_ownership(app):
        category = "Unapproved Enterprise AI"
        reasons.append("Business sahipli ama onaylanmamış")
    elif ownership == "Internal":
        category = "Internal Custom AI"
        reasons.append("İç geliştirilmiş uygulama")
    elif signal in ("app_id", "pattern", "domain") and ownership == "External":
        if _personal_pattern(app):
            category = "Personal AI Usage"
            reasons.append("Kişisel kullanım deseni (tek kullanıcı, user-consent)")
        else:
            category = "Third-Party Shadow AI"
            reasons.append("Yönetilmeyen 3. parti AI")
    else:
        # Kriter: Unknown güvenli/approved sayılmaz — ayrı incelemeye düşer
        category = "Unknown AI"
        confidence = min(confidence, 40)
        reasons.append("Sınıflandırma kesin değil — inceleme gerekli")

    return {
        "category": category,
        "ownership": ownership,
        "confidence": confidence,
        "reasons": reasons,
        "manual_override": False,
    }


def classify_all(findings, home_tenant):
    for f in findings:
        f["classification"] = classify(f, home_tenant)
    return findings
