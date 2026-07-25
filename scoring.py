"""
Şeffaf risk skorlama. Her app 0-100 arası skor ve gerekçe alır.

Skorun bileşenleri (toplanır, 100'de kırpılır):
  - scope hassasiyeti  : verilen izinlerin toplam ağırlığı (en büyük ağırlık)
  - blast radius        : admin (AllPrincipals) onayı + etkilenen kullanıcı sayısı
  - güven/verifikasyon  : doğrulanmamış publisher cezası
  - kalıcılık           : offline_access (refresh token) cezası

Amaç: skoru "kutu" değil, savunulabilir bir gerekçe zinciriyle vermek.
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

    # 1) Scope hassasiyeti — en riskli birkaç iznin ağırlığı
    weighted = sorted(((_scope_weight(s), s) for s in app["scopes"]), reverse=True)
    top = weighted[:4]
    scope_points = sum(w for w, _ in top) * 3  # 0..~120
    if scope_points:
        score += min(scope_points, 55)
        hot = ", ".join(s for _, s in top if _ >= 6)
        if hot:
            reasons.append(f"Hassas veri izinleri: {hot}")

    # 2) Blast radius
    if app["consent_type"] == "AllPrincipals":
        score += 20
        reasons.append("Admin onayı (AllPrincipals): izin TÜM organizasyon için geçerli")
    if app["user_count"] >= 10:
        score += 10
        reasons.append(f"{app['user_count']} kullanıcı bu uygulamaya erişim vermiş")
    elif app["user_count"] > 0:
        score += 4

    # 3) Güven
    if not app["verified_publisher"]:
        score += 10
        reasons.append("Publisher doğrulanmamış (verified publisher yok)")
    if app["third_party"]:
        reasons.append("Dış tenant'a ait 3. parti uygulama (veri org dışına çıkabilir)")

    # 4) Kalıcılık
    if "offline_access" in app["scopes"]:
        score += 6
        reasons.append("offline_access: kalıcı erişim (refresh token) — iptal edilmedikçe sürer")

    # 5) Düşük güvenli tespit için not
    if app["confidence"] == "low":
        reasons.append("AI olduğu jenerik eşleşmeyle tahmin edildi — manuel doğrula")

    score = max(0, min(100, score))
    app["risk_score"] = score
    app["risk_level"] = ("Kritik" if score >= 75 else "Yüksek" if score >= 50
                         else "Orta" if score >= 25 else "Düşük")
    app["reasons"] = reasons or ["Belirgin hassas izin bulunmadı"]
    app["remediation"] = _remediation(app)
    return app


def _remediation(app: dict) -> list[str]:
    steps = []
    if app["consent_type"] == "AllPrincipals":
        steps.append("Entra > Enterprise apps > bu app > Permissions: admin consent'i gözden geçir/kaldır")
    if not app["verified_publisher"]:
        steps.append("Doğrulanmamış publisher: kullanımı onayla veya engelle (app consent policy)")
    if any(_scope_weight(s) >= 9 for s in app["scopes"]):
        steps.append("Yüksek izinli scope'ları revoke et; least-privilege alternatifini değerlendir")
    steps.append("Gerekmiyorsa: Enterprise app'i sil veya kullanıcı atamalarını kaldır")
    steps.append("User consent'i kısıtla: yalnızca doğrulanmış publisher + düşük riskli izinler")
    return steps


def score_all(apps: list[dict]) -> list[dict]:
    scored = [score_app(a) for a in apps]
    scored.sort(key=lambda a: a["risk_score"], reverse=True)
    return scored
