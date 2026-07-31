"""
Classification engine — sorts AI applications into governance categories.

Signals (in order of strength): manual override > app_id match > publisher/name/domain >
business metadata / lifecycle > generic. Unknown is NEVER treated as safe/approved.

Categories: config.AI_CATEGORIES. Ownership: Internal / External / Unknown.
Output attaches `classification` = {category, ownership, confidence, reasons, manual_override} to each app.
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
    """Personal usage: third-party, user-consent, single/few users, no admin consent."""
    return (app.get("third_party")
            and app.get("consent_type") == "Principal"
            and app.get("user_count", 0) <= 2
            and not app.get("has_app_only_access"))


def classify(app, home_tenant):
    ownership = _ownership(app, home_tenant)

    # 1) Manual override — strongest signal, preserved (comes from the metadata store)
    override = app.get("classification_override") or {}
    if override.get("category"):
        return {
            "category": override["category"],
            "ownership": override.get("ownership") or ownership,
            "confidence": 100,
            "reasons": ["Manual override (admin classification)"],
            "manual_override": True,
        }

    reasons = []
    signal = app.get("match_signal")
    vendor = app.get("vendor", "")
    status = (app.get("lifecycle") or {}).get("status")

    # Confidence + match reason
    if signal == "app_id":
        confidence = 95
        reasons.append(f"Known application App ID ({vendor})")
    elif signal in ("pattern", "domain"):
        confidence = 72
        reasons.append(f"Publisher/name/domain match ({vendor})")
    else:
        confidence = 45
        reasons.append("Generic AI match (not certain)")

    if app.get("verified_publisher"):
        reasons.append("Verified publisher")
        confidence = min(100, confidence + 5)
    if ownership == "External":
        reasons.append("External publisher tenant")
    elif ownership == "Internal":
        reasons.append("Internal (home tenant) application")

    # 2) Category — in priority order
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
        reasons.append("Has a business owner but not approved")
    elif ownership == "Internal":
        category = "Internal Custom AI"
        reasons.append("Internally developed application")
    elif signal in ("app_id", "pattern", "domain") and ownership == "External":
        if _personal_pattern(app):
            category = "Personal AI Usage"
            reasons.append("Personal usage pattern (single user, user-consent)")
        else:
            category = "Third-Party Shadow AI"
            reasons.append("Ungoverned third-party AI")
    else:
        # Criterion: Unknown is not treated as safe/approved — falls to separate review
        category = "Unknown AI"
        confidence = min(confidence, 40)
        reasons.append("Classification is not certain — needs review")

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
