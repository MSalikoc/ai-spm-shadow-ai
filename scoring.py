"""
Transparent risk scoring. Every app gets a 0-100 score and a reason chain.

Score components (additive, clipped at 100):
  - scope sensitivity   : total weight of the granted permissions (top few)
  - blast radius        : admin (AllPrincipals) consent + affected user count
  - trust/verification  : unverified publisher penalty
  - persistence         : offline_access (refresh token) penalty

Goal: give a defensible reason chain for the score, not a black box.
"""
from config import SENSITIVE_SCOPES, SCOPE_HEURISTICS


def _scope_weight(scope: str) -> int:
    if scope in SENSITIVE_SCOPES:
        return SENSITIVE_SCOPES[scope]
    for frag, w in SCOPE_HEURISTICS:
        if frag in scope:
            return w
    return 1


def score_app(app: dict) -> dict:
    reasons: list[str] = []
    score = 0

    # 1) Scope sensitivity — weight of the riskiest few permissions
    weighted = sorted(((_scope_weight(s), s) for s in app["scopes"]), reverse=True)
    top = weighted[:4]
    scope_points = sum(w for w, _ in top) * 3  # 0..~120
    if scope_points:
        score += min(scope_points, 55)
        hot = ", ".join(s for _, s in top if _ >= 6)
        if hot:
            reasons.append(f"Sensitive data permissions: {hot}")

    # 2) Blast radius
    if app["consent_type"] == "AllPrincipals":
        score += 20
        reasons.append("Admin consent (AllPrincipals): permission applies to the ENTIRE organization")
    if app["user_count"] >= 10:
        score += 10
        reasons.append(f"{app['user_count']} users have granted this app access")
    elif app["user_count"] > 0:
        score += 4

    # 3) Trust
    if not app["verified_publisher"]:
        score += 10
        reasons.append("Publisher not verified (no verified publisher)")
    if app["third_party"]:
        reasons.append("Third-party app owned by an external tenant (data may leave the org)")

    # 4) Persistence
    if "offline_access" in app["scopes"]:
        score += 6
        reasons.append("offline_access: persistent access (refresh token) — lasts until revoked")

    # 5) Application (app-only) permissions — no user required, 24/7, tenant-wide.
    #    Can be more dangerous than delegated; weighted higher.
    app_perms = app.get("application_permissions", [])
    if app_perms:
        ap_weighted = sorted((_scope_weight(p["permission"].lower()) for p in app_perms),
                             reverse=True)
        score += min(sum(ap_weighted[:4]) * 4, 45)
        hot_ap = [p["permission"] for p in app_perms
                  if _scope_weight(p["permission"].lower()) >= 6][:3]
        note = f": {', '.join(hot_ap)}" if hot_ap else ""
        reasons.append(f"App-only access (no user required, entire tenant){note}")

    # 6) Note for low-confidence detection
    if app["confidence"] == "low":
        reasons.append("Identified as AI via a generic match — verify manually")

    score = max(0, min(100, score))
    app["risk_score"] = score
    app["risk_level"] = ("Critical" if score >= 75 else "High" if score >= 50
                         else "Medium" if score >= 25 else "Low")
    app["reasons"] = reasons or ["No notable sensitive permissions found"]
    app["remediation"] = _remediation(app)
    return app


def _remediation(app: dict) -> list[str]:
    steps = []
    if app["consent_type"] == "AllPrincipals":
        steps.append("Entra > Enterprise apps > this app > Permissions: review/remove admin consent")
    if not app["verified_publisher"]:
        steps.append("Unverified publisher: approve or block usage (app consent policy)")
    if any(_scope_weight(s) >= 9 for s in app["scopes"]):
        steps.append("Revoke high-privilege scopes; evaluate a least-privilege alternative")
    if any(_scope_weight(p["permission"].lower()) >= 8 for p in app.get("application_permissions", [])):
        steps.append("Review app-only application permissions — unattended, tenant-wide access")
    steps.append("If not needed: delete the Enterprise app or remove user assignments")
    steps.append("Restrict user consent: verified publishers and low-risk permissions only")
    return steps


def score_all(apps: list[dict]) -> list[dict]:
    scored = [score_app(a) for a in apps]
    scored.sort(key=lambda a: a["risk_score"], reverse=True)
    return scored
