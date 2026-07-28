"""
Microsoft AI Data Sources — birleşik assessment/rapor (Adım 7).

`report.py` (mevcut Entra/OAuth dashboard'u) HİÇ DEĞİŞTİRİLMEDİ; bu modül tamamen ayrı,
standalone bir sayfa üretir (aynı CSS/tema diliyle — `report.CSS` içe aktarılır, kopyalanmaz).
Girdi `pipeline.run_connectors()`'ın döndürdüğü sonuç sözlüğü (assets/coverage/health/
counts/profiles/portfolio) — connector'lar env-flag ile kapalıysa bu modül hiç çağrılmaz.

15 bölüm (assessment(result) sözlük anahtarları):
 1. executive            — portfolio özeti (apps_with_sensitive_data, affected_users, findings…)
 2. data_source_coverage — 5 connector'ın health/permission/lisans durumu (dürüst, uydurma yok)
 3. sensitive_exposure   — "Applications with Sensitive Data Exposure" tablosu (Adım 7 kabul kriteri)
 4. agent_identities      — Entra Agent ID envanteri (owner/sponsor/perm ayrımı)
 5. agent365_packages     — Agent 365 paket envanteri (build_type/blocked/scope)
 6. shadow_ai_usage       — Defender/MDCA keşfedilen AI app'leri (sanctioned/upload/risk)
 7. sensitive_interactions— Purview audit özet (blocked/allowed/SIT)
 8. findings              — evaluate_findings çıktısı, önem sırasına göre
 9. direction_analysis    — ACCESSED/SHARED/UPLOADED/GENERATED/BLOCKED/ALLOWED/UNKNOWN dağılımı
10. correlation_quality   — confidence dağılımı + kaynak-başına uncorrelated sayaçları
11. application_detail    — her app için "Sensitive Data" sekmesi içeriği (Adım 7 kabul kriteri)
12. agent_detail          — her identity için "Data Access" sekmesi içeriği (owners/sponsors/perms)
13. sit_distribution      — estate-geneli SIT/label dağılımı
14. users_and_groups      — en çok etkilenen kullanıcılar + owner/sponsor'suz grup üyelikleri
15. known_gaps            — API'de olmayan alanlar + bilinen korelasyon eksikleri (dürüst coverage)

HTML görünümü (html_string), Microsoft'un Zero Trust Assessment aracındaki "assessment
sonuçları" desenini izler: her madde (agent/uygulama/bulgu) filtrelenebilir bir tabloda
satır olarak listelenir (Risk + Status rozetleri); satıra tıklayınca sağdan bir panel açılır
(facts satırı → Result → What was checked → Remediation action). Bu bir client-side
vanilla-JS bileşenidir (bağımsız, framework yok); veri `assessment()`'tan gelir.
"""
import html
import json
from datetime import datetime, timezone

from connectors.agent365 import metrics as agent365_metrics
from connectors.base import ConnectorStatus
from connectors.defender_cloud_apps import metrics as mdca_metrics
from connectors.entra_agent_id import metrics as entra_agent_metrics
from connectors.purview_audit import metrics as purview_metrics
from report import CSS

_CONNECTOR_INFO = {
    "agent365": ("Microsoft Agent 365", "CopilotPackages.Read.All"),
    "entra_agent_id": ("Microsoft Entra Agent ID", "Application.Read.All + Directory.Read.All"),
    "defender_cloud_apps": ("Defender for Cloud Apps (Shadow AI)", "CloudApp-Discovery.Read.All"),
    "purview_audit": ("Microsoft Purview Audit", "AuditLogsQuery.Read.All"),
    "purview_dspm_import": ("Purview DSPM import (dosya)", "n/a — dosya import"),
}


def assessment(result: dict, now=None) -> dict:
    """
    `pipeline.run_connectors()` çıktısından 15-bölümlü assessment sözlüğü üretir.

    NOT: Korelasyon farklı kaynaklardan gelen asset'leri birleştirdiğinde, birleşik
    asset'in `asset_type`'ı ilk üyeden (index sırasına göre) miras kalır — ör. Agent365
    paketiyle aynı entra_app_id üzerinden korele olan bir Entra Agent Identity, birleşik
    asset'te `asset_type=AI_AGENT` görünebilir ama `agent_identity` alt-dict'i hâlâ
    taşınır. Bu yüzden burada (ve connector `metrics()` fonksiyonlarında olduğu gibi)
    filtreleme `asset_type` eşitliğiyle DEĞİL, connector'a özel alt-dict anahtarının
    varlığıyla yapılır.
    """
    now = now or datetime.now(timezone.utc)
    assets = result.get("assets", [])
    coverage = result.get("coverage", {})
    health = result.get("health", {})
    profiles = result.get("profiles", [])
    portfolio = result.get("portfolio", {})

    agent365 = [a for a in assets if a.get("agent365")]
    identities = [a for a in assets if a.get("agent_identity")]
    blueprints = [a for a in assets if a.get("agent_blueprint")]
    ai_apps = [a for a in assets if a.get("mdca")]
    interactions = [a for a in assets if a.get("interaction")]

    return {
        "executive": _executive(portfolio, health),
        "data_source_coverage": _coverage_section(coverage, health),
        "sensitive_exposure": _sensitive_exposure(profiles),
        "agent_identities": _agent_identities(identities, entra_agent_metrics(assets)),
        "agent365_packages": _agent365_section(agent365, agent365_metrics(assets)),
        "shadow_ai_usage": _shadow_ai(ai_apps, mdca_metrics(assets)),
        "sensitive_interactions": _sensitive_interactions(interactions, purview_metrics(assets)),
        "findings": _findings(profiles),
        "direction_analysis": _direction_analysis(profiles),
        "correlation_quality": _correlation_quality(assets),
        "application_detail": _application_detail(profiles),
        "agent_detail": _agent_detail(identities, blueprints),
        "sit_distribution": _sit_distribution(profiles),
        "users_and_groups": _users_and_groups(profiles, identities),
        "known_gaps": _known_gaps(coverage),
        "_generated_at": now.isoformat(),
    }


# ---------- bölüm oluşturucular ----------
def _executive(portfolio, health):
    connected = sum(1 for h in health.values() if h.get("status") == ConnectorStatus.CONNECTED)
    return {**portfolio, "connectors_connected": connected, "connectors_total": len(health)}


def _coverage_section(coverage, health):
    rows = []
    for name, (label, perm) in _CONNECTOR_INFO.items():
        h = health.get(name, {})
        rows.append({
            "name": name, "label": label, "permission": perm,
            "status": h.get("status", ConnectorStatus.NOT_CONFIGURED),
            "count": h.get("count", 0), "error": h.get("error"),
            "coverage": coverage.get(name, {}),
        })
    return rows


def _sensitive_exposure(profiles):
    rows = [p for p in profiles if p["sensitive_data_summary"]["window_30d"]["sensitive"] > 0]
    return sorted(rows, key=lambda p: p["sensitive_data_summary"]["window_30d"]["sensitive"],
                 reverse=True)


def _agent_identities(identities, m):
    rows = [{
        "display_name": a.get("display_name"),
        "enabled": (a.get("agent_identity") or {}).get("account_enabled"),
        "owners": [o.get("upn") or o.get("display_name")
                   for o in (a.get("agent_identity") or {}).get("owners", [])],
        "sponsors": [s.get("upn") or s.get("display_name")
                     for s in (a.get("agent_identity") or {}).get("sponsors", [])],
        "app_only_perms": len((a.get("agent_identity") or {}).get("application_permissions", [])),
        "delegated_perms": len((a.get("agent_identity") or {}).get("delegated_permissions", [])),
        "blueprint_id": (a.get("related") or {}).get("blueprint_id")
                        or (a.get("agent_identity") or {}).get("blueprint_id"),
        "entra_app_id": (a.get("external_ids") or {}).get("entra_app_id"),
    } for a in identities]
    return {"metrics": m, "identities": rows}


def _agent365_section(agents, m):
    rows = [{
        "display_name": a.get("display_name"),
        "build_type": (a.get("agent365") or {}).get("build_type"),
        "blocked": (a.get("agent365") or {}).get("blocked"),
        "available_to": (a.get("agent365") or {}).get("available_to"),
        "deployed_to": (a.get("agent365") or {}).get("deployed_to"),
        "entra_app_id": (a.get("external_ids") or {}).get("entra_app_id"),
    } for a in agents]
    return {"metrics": m, "packages": rows}


def _shadow_ai(apps, m):
    rows = sorted([{
        "display_name": a.get("display_name"),
        "sanctioned_state": (a.get("mdca") or {}).get("sanctioned_state"),
        "users": (a.get("mdca") or {}).get("users", 0),
        "uploaded_bytes": (a.get("mdca") or {}).get("uploaded_bytes", 0),
        "risk_score": (a.get("mdca") or {}).get("risk_score"),
        "data_sensitivity": (a.get("mdca") or {}).get("data_sensitivity"),
    } for a in apps], key=lambda r: r["uploaded_bytes"], reverse=True)
    return {"metrics": m, "applications": rows}


def _sensitive_interactions(interactions, m):
    return {"metrics": m, "sample": [{
        "user": (i.get("interaction") or {}).get("user"),
        "app_host": (i.get("interaction") or {}).get("app_host"),
        "direction": (i.get("interaction") or {}).get("direction"),
        "sits": [s.get("name") for s in (i.get("interaction") or {}).get("sensitive_info_types", [])],
        "timestamp": (i.get("interaction") or {}).get("timestamp"),
    } for i in interactions[:25]]}


def _findings(profiles):
    findings = [dict(f, app_key=p["app_key"]) for p in profiles for f in p["findings"]]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(findings, key=lambda f: order.get(f["severity"], 9))


def _direction_analysis(profiles):
    totals = {}
    for p in profiles:
        for d, n in p["directions"].items():
            totals[d] = totals.get(d, 0) + n
    return totals


def _correlation_quality(assets):
    buckets = {"high_98_100": 0, "medium_65_97": 0, "name_only_or_single": 0}
    uncorrelated_by_source = {}
    for a in assets:
        conf = a.get("correlation_confidence")
        if conf is None:
            continue
        if conf >= 98:
            buckets["high_98_100"] += 1
        elif conf >= 65:
            buckets["medium_65_97"] += 1
        else:
            buckets["name_only_or_single"] += 1
        if len(a.get("sources", [])) == 1 and conf == 100:
            for s in a["sources"]:
                uncorrelated_by_source[s] = uncorrelated_by_source.get(s, 0) + 1
    return {"confidence_buckets": buckets, "single_source_by_connector": uncorrelated_by_source}


def _application_detail(profiles):
    """Application Detail 'Sensitive Data' sekmesi içeriği (Adım 7 kabul kriteri)."""
    return [{
        "app_key": p["app_key"], "display_name": p["display_name"],
        "matched_to_inventory": p["matched_to_inventory"],
        "sanctioned_state": p.get("sanctioned_state"),
        "sensitive_data_summary": p["sensitive_data_summary"],
        "sit_distribution": p["sit_distribution"],
        "directions": p["directions"],
        "findings": p["findings"],
    } for p in profiles]


def _agent_detail(identities, blueprints):
    """Agent Detail 'Data Access' sekmesi içeriği (owners/sponsors/perms/groups)."""
    bp_by_id = {b["asset_id"]: b for b in blueprints}
    rows = []
    for a in identities:
        ai = a.get("agent_identity") or {}
        rel = a.get("related") or {}
        bp = bp_by_id.get(rel.get("blueprint_asset_id"))
        rows.append({
            "display_name": a.get("display_name"),
            "account_enabled": ai.get("account_enabled"),
            "owners": ai.get("owners", []),
            "sponsors": ai.get("sponsors", []),
            "application_permissions": ai.get("application_permissions", []),
            "delegated_permissions": ai.get("delegated_permissions", []),
            "group_memberships": ai.get("group_memberships", []),
            "blueprint": {"display_name": bp.get("display_name")} if bp else None,
        })
    return rows


def _sit_distribution(profiles):
    agg = {}
    for p in profiles:
        for sit, n in p["sit_distribution"].items():
            agg[sit] = agg.get(sit, 0) + n
    return dict(sorted(agg.items(), key=lambda kv: kv[1], reverse=True))


def _users_and_groups(profiles, identities):
    user_counts = {}
    for p in profiles:
        for u in p["affected_users"]:
            user_counts[u] = user_counts.get(u, 0) + 1
    top_users = sorted(user_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
    groups_without_owner = [
        {"display_name": a.get("display_name"),
         "groups": [g.get("display_name") for g in (a.get("agent_identity") or {}).get("group_memberships", [])]}
        for a in identities if not (a.get("agent_identity") or {}).get("owners")
        and (a.get("agent_identity") or {}).get("group_memberships")
    ]
    return {"top_affected_users": top_users, "identities_without_owner_but_in_groups": groups_without_owner}


def _known_gaps(coverage):
    gaps = []
    for name, (label, _) in _CONNECTOR_INFO.items():
        if not coverage.get(name):
            gaps.append(f"{label}: coverage verisi yok (connector hiç çalışmadı).")
        elif coverage[name].get("status") in (ConnectorStatus.NOT_CONFIGURED,):
            gaps.append(f"{label}: bağlı değil — bu kaynağa ait envanter/hassaslık verisi YOK "
                        f"(uydurma envanter üretilmedi, dürüstçe boş).")
    gaps.append("Purview audit'te sensitivity_label_name API'de yok (field=NOT_EXPOSED_BY_API); "
               "yalnızca label_id mevcut.")
    gaps.append("MDCA upload hacmi tek başına 'hassas paylaşım' sayılmaz; Purview korelasyonu "
               "yoksa data_sensitivity=UNDETERMINED_REQUIRES_PURVIEW kalır.")
    gaps.append("agent_blueprint_id merge token'ı DEĞİL (relate-not-merge); aynı blueprint'ten "
               "türeyen birden fazla identity ayrı asset olarak kalır.")
    return gaps


# ---------- JSON çıktı ----------
def json_string(result: dict, now=None) -> str:
    return json.dumps(assessment(result, now), ensure_ascii=False, indent=2, default=str)


# ---------- ortak HTML yardımcıları ----------
_SEV = {"high": "#c0392b", "medium": "#b8860b", "low": "#2e8b57", "info": "#6b7280"}
_RISK_LABEL = {"high": "Yüksek", "medium": "Orta", "low": "Düşük", "info": "Bilgi"}


def _esc(s):
    return html.escape(str(s)) if s is not None else "—"


def _status_color(status):
    return {ConnectorStatus.CONNECTED: "#2e8b57", ConnectorStatus.PARTIALLY_CONNECTED: "#b8860b",
           ConnectorStatus.NOT_CONFIGURED: "#6b7280", ConnectorStatus.PERMISSION_MISSING: "#c0392b",
           ConnectorStatus.LICENSE_MISSING: "#c0392b", ConnectorStatus.NO_DATA: "#6b7280",
           ConnectorStatus.API_UNAVAILABLE: "#d35400", ConnectorStatus.ERROR: "#c0392b"}.get(status, "#6b7280")


def _coverage_html(rows):
    items = "".join(
        f'<li><span class="dot" style="background:{_status_color(r["status"])}"></span>'
        f'<b>{_esc(r["label"])}</b> — {_esc(r["status"])} · {_esc(r["count"])} varlık '
        f'· <span style="color:var(--muted)">{_esc(r["permission"])}</span></li>'
        for r in rows)
    return f'<ul class="conn">{items}</ul>'


def _table(headers, rows_html, empty_msg):
    if not rows_html:
        return f'<div class="empty">{_esc(empty_msg)}</div>'
    ths = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return (f'<div class="c-tbl-wrap"><table class="c-tbl"><thead><tr>{ths}</tr></thead>'
           f'<tbody>{"".join(rows_html)}</tbody></table></div>')


def _tags(values):
    spans = [f'<span class="c-tag">{_esc(v)}</span>' for v in values]
    return "".join(spans) or "—"


def _interactions_table(sample):
    trs = [
        f'<tr><td class="c-num">{_esc(i.get("timestamp"))}</td><td class="c-name">{_esc(i.get("app_host"))}</td>'
        f'<td>{_esc(i.get("user"))}</td><td><span class="c-tag">{_esc(i.get("direction"))}</span></td>'
        f'<td>{_tags(i.get("sits") or [])}</td></tr>'
        for i in sample]
    return _table(["Zaman", "Uygulama", "Kullanıcı", "Yön", "Veri türü"], trs,
                 "Purview'da hassas etkileşim yok (veya kaynak bağlı değil).")


# ---------- klasik dashboard'un (report.py) görsel dilini yeniden kullanan yardımcılar ----------
# report.py'ye DOKUNULMUYOR — sadece aynı CSS (import edilen `CSS`) üzerine, aynı bileşen
# desenleriyle (donut/bars/kpi-grid) kendi, bağımsız bir sayfa kuruyoruz.
def _donut(segments, size=180, stroke=28, center_label="Bulgu"):
    import math
    total = sum(v for _, v, _ in segments) or 1
    r = (size - stroke) / 2
    cx = cy = size / 2
    circ = 2 * math.pi * r
    offset = 0.0
    arcs = []
    for _, value, color in segments:
        if value <= 0:
            continue
        dash = circ * (value / total)
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>')
        offset += dash
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" class="donut">'
        f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="var(--track)" stroke-width="{stroke}"/>'
        f'{"".join(arcs)}'
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" class="donut-num">{total}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="donut-cap">{_esc(center_label)}</text>'
        f'</svg>')


def _bars(rows, maxv):
    """rows: [(label, sublabel, value, color)] → report.py ile aynı bar-row deseni."""
    maxv = maxv or 1
    out = []
    for label, sub, value, color in rows:
        pct = max(3, round(100 * value / maxv))
        out.append(
            f'<div class="bar-row"><div class="bar-label">{_esc(label)}'
            f'<span class="bar-sub">{_esc(sub)}</span></div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;'
            f'background:{color}"></div></div>'
            f'<div class="bar-val">{value}</div></div>')
    return "".join(out) or '<div class="empty">Veri yok</div>'


# Gerçek Microsoft logosu (4 renkli kare) — inline SVG, harici kaynağa bağımlılık yok.
_MS_LOGO_SVG = """<svg width="21" height="21" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
<rect x="1" y="1" width="9" height="9" fill="#F25022"/>
<rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
<rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
<rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
</svg>"""


# ==================================================================================
# "Assessment results" bileşeni — Microsoft Zero Trust Assessment aracındaki desen:
# filtrelenebilir/aranabilir tablo (Ad | Risk | Status) + satıra tıklayınca açılan
# yan panel (facts → Result → What was checked → Remediation action).
# Her madde tipi (Agent 365 paketi, Entra identity, Shadow AI app, hassas veri
# exposure'ı, bulgu) kendi _*_items() fonksiyonuyla bu ortak şemaya çevrilir:
#   {id, name, risk_label, risk_color, status_label, status_color,
#    facts:[(label,value),...], result_line, what_checked, remediation:[str,...]}
# ==================================================================================
def _item(item_id, name, risk_label, risk_color, status_label, status_color,
         facts, result_line, what_checked, remediation):
    return {
        "id": item_id, "name": name,
        "risk_label": risk_label, "risk_color": risk_color,
        "status_label": status_label, "status_color": status_color,
        "facts": facts, "result_line": result_line, "what_checked": what_checked,
        "remediation": remediation if isinstance(remediation, list) else [remediation],
    }


def _agent365_items(packages):
    items = []
    for idx, p in enumerate(packages):
        name, build_type = p["display_name"], p["build_type"] or "bilinmiyor"
        deployed_to, available_to = p["deployed_to"] or "belirsiz", p["available_to"] or "belirsiz"
        available_all = available_to.strip().lower() in ("everyone", "all", "alltenant", "organization")
        correlated = bool(p.get("entra_app_id"))

        if p["blocked"]:
            risk, status, status_c = "info", "Blocked", _SEV["high"]
            result_line = "Paket engellenmiş durumda."
            remediation = ["Engelleme nedenini yayıncı/sorumlu ekiple doğrulayın; gerekmiyorsa kaldırmayın."]
        elif available_all and not correlated:
            risk, status, status_c = "high", "Investigate", _SEV["medium"]
            result_line = "Herkese açık ve Entra kimliğiyle korele değil."
            remediation = ["Paketin kime açık olduğunu (deployment scope) daraltın.",
                          "Entra Agent ID ile korelasyon için ilgili appId'yi doğrulayın."]
        elif available_all:
            risk, status, status_c = "medium", "Investigate", _SEV["medium"]
            result_line = "Herkese açık dağıtım."
            remediation = ["Dağıtım kapsamının iş gerekliliğiyle örtüştüğünü doğrulayın."]
        else:
            risk, status, status_c = "low", "Passed", _SEV["low"]
            result_line = "Kapsamı sınırlı, ek risk sinyali yok."
            remediation = ["Ek aksiyon gerekmiyor; periyodik olarak gözden geçirin."]

        what_checked = (
            f"{name}, Agent 365 kataloğunda kayıtlı bir {build_type} pakettir. "
            f"{deployed_to} kapsamına deploy edilmiş ve {available_to} kullanıcılara açık. "
            + ("Paket şu anda engellenmiş durumda. " if p["blocked"] else "Paket aktif ve engellenmemiş. ")
            + (f"Entra uygulaması ile korele: {p['entra_app_id']}."
               if correlated else "Herhangi bir Entra uygulamasıyla korele değil.")
        )
        facts = [("Risk", _RISK_LABEL[risk]), ("Build Type", build_type), ("Deployment", deployed_to)]
        items.append(_item(f"agent365-{idx}", name, risk, _SEV[risk], status, status_c,
                          facts, result_line, what_checked, remediation))
    return items


def _identity_items(identities):
    items = []
    for idx, i in enumerate(identities):
        name = i["display_name"]
        has_owner, has_sponsor = bool(i["owners"]), bool(i["sponsors"])
        perm_type = ("app-only + delegated" if i["app_only_perms"] and i["delegated_perms"]
                    else "yalnızca app-only" if i["app_only_perms"]
                    else "yalnızca delegated" if i["delegated_perms"] else "izin yok")

        if not i["enabled"]:
            risk, status, status_c = "info", "Disabled", _SEV["info"]
            result_line = "Devre dışı — aktif erişim riski yok."
            remediation = ["Ek aksiyon gerekmiyor; kullanılmıyorsa kaldırılmasını değerlendirin."]
        elif has_owner and has_sponsor:
            risk, status, status_c = "low", "Passed", _SEV["low"]
            result_line = "Owner ve sponsor atanmış."
            remediation = ["Ek aksiyon gerekmiyor."]
        elif has_owner or has_sponsor:
            risk, status, status_c = "medium", "Investigate", _SEV["medium"]
            result_line = "Owner veya sponsor eksik."
            remediation = ["Eksik olan (owner veya sponsor) atamasını tamamlayın."]
        else:
            risk, status, status_c = "high", "Failed", _SEV["high"]
            result_line = "Owner ve sponsor atanmamış."
            remediation = ["Bu agent identity'sine bir owner atayın — hesap verebilirlik için gereklidir.",
                          "Bir sponsor atayın (özellikle app-only izinleri varsa)."]

        what_checked = (
            f"{name} " + ("etkin (enabled) durumda. " if i["enabled"] else "devre dışı (disabled) durumda. ")
            + f"Owner: {', '.join(i['owners']) if has_owner else 'atanmamış'}. "
            + f"Sponsor: {', '.join(i['sponsors']) if has_sponsor else 'atanmamış'}. "
            + f"{i['app_only_perms']} app-only ve {i['delegated_perms']} delegated izne sahip ({perm_type}). "
            + (f"Blueprint: {i['blueprint_id']}." if i.get("blueprint_id") else "Herhangi bir blueprint'e bağlı değil.")
        )
        facts = [("Risk", _RISK_LABEL[risk]), ("Owner Coverage", "Var" if has_owner else "Yok"),
                ("Permission Type", perm_type)]
        items.append(_item(f"identity-{idx}", name, risk, _SEV[risk], status, status_c,
                          facts, result_line, what_checked, remediation))
    return items


def _shadow_items(apps):
    items = []
    for idx, a in enumerate(apps):
        name, state = a["display_name"], a.get("sanctioned_state")
        high_risk_score = isinstance(a.get("risk_score"), int) and a["risk_score"] <= 3

        if state == "unsanctioned" or high_risk_score:
            risk, status, status_c = "high", "Failed", _SEV["high"]
            result_line = "Onaysız (unsanctioned) uygulama."
            remediation = ["Uygulamayı Defender for Cloud Apps'te sanctioned veya blocked olarak işaretleyin.",
                          "Kullanıcıları onaylı bir alternatife yönlendirin."]
        elif state == "unreviewed":
            risk, status, status_c = "medium", "Investigate", _SEV["medium"]
            result_line = "Henüz gözden geçirilmedi."
            remediation = ["Uygulamayı gözden geçirip sanctioned/unsanctioned olarak sınıflandırın."]
        elif state == "sanctioned":
            risk, status, status_c = "low", "Passed", _SEV["low"]
            result_line = "Kurumsal onaylı (sanctioned)."
            remediation = ["Ek aksiyon gerekmiyor; periyodik olarak trafiği izlemeye devam edin."]
        else:
            risk, status, status_c = "info", "Investigate", _SEV["info"]
            result_line = "Onay durumu bilinmiyor."
            remediation = ["Onay durumunu MDCA'da belirleyin."]

        what_checked = (
            f"{name}, Defender for Cloud Apps tarafından son 30 günde {a['users']} kullanıcı ve "
            f"{a['uploaded_bytes']:,} bayt trafikle keşfedildi. Onay durumu: {state or 'bilinmiyor'}. "
            + (f"Risk skoru: {a['risk_score']}/10. " if a.get("risk_score") is not None else "")
            + f"Hassaslık durumu: {a.get('data_sensitivity') or 'bilinmiyor'} "
              "— Purview korelasyonu olmadan kesinleşmez."
        )
        facts = [("Risk", _RISK_LABEL[risk]), ("Onay Durumu", state or "—"), ("Kullanıcı (30g)", a["users"])]
        items.append(_item(f"shadow-{idx}", name, risk, _SEV[risk], status, status_c,
                          facts, result_line, what_checked, remediation))
    return items


def _exposure_items(rows):
    items = []
    for idx, p in enumerate(rows):
        s = p["sensitive_data_summary"]
        name = p["display_name"]
        dirs = ", ".join(f"{k}:{v}" for k, v in p["directions"].items() if v) or "yok"

        if s["allowed"] > 0:
            risk, status, status_c = "high", "Failed", _SEV["high"]
            result_line = "DLP eşleşti ama izin verildi — inceleme gerekli."
        elif s["blocked"] > 0:
            risk, status, status_c = "low", "Passed", _SEV["low"]
            result_line = "Tüm hassas etkileşimler engellendi."
        else:
            risk, status, status_c = "medium", "Investigate", _SEV["medium"]
            result_line = "Erişim var ama DLP eşleşmesi/engeli yok."

        what_checked = (
            f"{name} son 30 günde {s['window_30d']['sensitive']}/{s['window_30d']['interactions']} "
            f"hassas etkileşime sahip, {p['affected_user_count']} kullanıcıyı etkiliyor. "
            f"Veri türleri: {', '.join(s['sit_types']) or 'yok'}. Yön dağılımı: {dirs}. "
            f"{s['blocked']} engellendi, {s['allowed']} izin verildi."
        )
        remediation = [f["detail"] for f in p["findings"]] or ["Ek aksiyon gerekmiyor."]
        facts = [("Risk", _RISK_LABEL[risk]), ("Etkilenen Kullanıcı", p["affected_user_count"]),
                ("Hassas Etkileşim (30g)", s["window_30d"]["sensitive"])]
        items.append(_item(f"exposure-{idx}", name, risk, _SEV[risk], status, status_c,
                          facts, result_line, what_checked, remediation))
    return items


_FINDING_REMEDIATION = {
    "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI":
        "Bu uygulamayı Defender for Cloud Apps'te sanctioned veya blocked olarak işaretleyin; "
        "DLP politikasını bu uygulamayı da kapsayacak şekilde genişletin; kullanıcıları onaylı "
        "bir alternatife yönlendirin.",
    "SENSITIVE_DATA_BLOCKED_TO_AI":
        "Pozitif kontrol — DLP politikası çalışıyor. Ek aksiyon gerekmez; politika kapsamını "
        "periyodik olarak gözden geçirin.",
    "AI_APP_ACCESSING_LABELED_DATA":
        "Bu uygulamanın etiketli veriye erişiminin iş gerekliliği olup olmadığını doğrulayın; "
        "gerekirse ek bir DLP politikası tanımlayın.",
    "UNSANCTIONED_AI_UPLOAD_UNDETERMINED":
        "Purview Audit/DSPM bağlantısını etkinleştirerek bu uygulamanın gerçek veri hassaslığını "
        "belirleyin; bağlanana kadar upload hacmini izlemeye devam edin.",
}
_DEFAULT_REMEDIATION = "Bulgu detayını inceleyip ilgili ekiple bir aksiyon planı oluşturun."


def _finding_items(findings):
    items = []
    for idx, f in enumerate(findings):
        risk = f["severity"] if f["severity"] in _SEV else "info"
        status, status_c = ("Passed", _SEV["low"]) if risk == "info" else ("Failed", _SEV[risk])
        facts = [("Risk", _RISK_LABEL[risk]), ("Uygulama", f.get("app") or "—"),
                ("Etkilenen Kullanıcı", f.get("affected_users", "—"))]
        items.append(_item(
            f"finding-{idx}", f["type"].replace("_", " ").title(), risk, _SEV[risk], status, status_c,
            facts, f["detail"], f["detail"], [_FINDING_REMEDIATION.get(f["type"], _DEFAULT_REMEDIATION)]))
    return items


def _zt_section(section_id, title, subtitle, items, empty_msg):
    if not items:
        return (f'<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>'
               f'<div class="empty">{_esc(empty_msg)}</div></div>')

    risks = sorted({it["risk_label"] for it in items}, key=lambda r: list(_RISK_LABEL.values()).index(r)
                  if r in _RISK_LABEL.values() else 9)
    statuses = sorted({it["status_label"] for it in items})

    risk_chips = "".join(
        f'<button class="zt-chip" data-scope="{section_id}" data-key="risk" data-val="{_esc(r)}" '
        f'onclick="ztChip(this)">{_esc(r)}</button>' for r in risks)
    status_chips = "".join(
        f'<button class="zt-chip" data-scope="{section_id}" data-key="status" data-val="{_esc(s)}" '
        f'onclick="ztChip(this)">{_esc(s)}</button>' for s in statuses)

    rows = []
    for it in items:
        detail_json = html.escape(json.dumps(it), quote=True)
        rows.append(
            f'<tr class="zt-row" data-scope="{section_id}" data-risk="{_esc(it["risk_label"])}" '
            f'data-status="{_esc(it["status_label"])}" data-name="{_esc(it["name"]).lower()}" '
            f"data-detail='{detail_json}' onclick=\"ztOpen(this)\">"
            f'<td class="c-name">{_esc(it["name"])}</td>'
            f'<td><span class="zt-pill" style="--pc:{it["risk_color"]}">{_esc(it["risk_label"])}</span></td>'
            f'<td><span class="zt-pill" style="--pc:{it["status_color"]}">{_esc(it["status_label"])}</span></td>'
            f'</tr>')

    return f"""
<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>
<div class="c-subtitle">{_esc(subtitle)}</div>
<div class="zt-toolbar">
  <input class="zt-search" data-scope="{section_id}" placeholder="Ara..." oninput="ztSearch(this)">
  <div class="zt-chips"><span class="zt-chip-label">Risk</span>{risk_chips}</div>
  <div class="zt-chips"><span class="zt-chip-label">Status</span>{status_chips}</div>
</div>
<div class="zt-tbl-wrap"><table class="zt-table"><thead><tr><th>Ad</th><th>Risk</th><th>Status</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</div>"""


_ZT_CSS = """
.c-subtitle{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;
 letter-spacing:.03em;margin:4px 0 10px}
.c-tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table.c-tbl{width:100%;border-collapse:collapse;font-size:13px;min-width:520px}
table.c-tbl thead th{text-align:left;font-size:11px;text-transform:uppercase;color:var(--muted);
 letter-spacing:.03em;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
table.c-tbl tbody td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
table.c-tbl tbody tr:last-child td{border-bottom:none}
.c-name{font-weight:600}
.c-num{font-variant-numeric:tabular-nums}
.c-tag{display:inline-block;font-size:11px;background:var(--track);color:var(--ink);
 padding:1px 7px;border-radius:5px;margin:1px 3px 1px 0}
header .navlink{text-decoration:none}
.zt-toolbar{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.zt-search{border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:8px;
 padding:7px 12px;font-size:13px;min-width:160px}
.zt-chips{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.zt-chip-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-right:2px}
.zt-chip{cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--ink);
 border-radius:999px;padding:4px 12px;font-size:12px}
.zt-chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}
table.zt-table{width:100%;border-collapse:collapse;font-size:13px;min-width:420px}
table.zt-table thead th{text-align:left;font-size:11px;text-transform:uppercase;color:var(--muted);
 letter-spacing:.03em;padding:9px 12px;border-bottom:1px solid var(--line)}
table.zt-table tbody td{padding:10px 12px;border-bottom:1px solid var(--line)}
table.zt-table tbody tr:last-child td{border-bottom:none}
table.zt-table tbody tr{cursor:pointer;transition:background .12s}
table.zt-table tbody tr:hover{background:var(--track)}
.zt-pill{display:inline-block;background:var(--pc,#6b7280);color:#fff;font-size:11px;font-weight:700;
 padding:3px 10px;border-radius:999px}
.zt-overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);opacity:0;pointer-events:none;
 transition:opacity .18s;z-index:20}
.zt-overlay.open{opacity:1;pointer-events:auto}
.zt-panel{position:fixed;top:0;right:0;bottom:0;width:min(480px,92vw);background:var(--panel);
 box-shadow:-8px 0 30px rgba(0,0,0,.18);transform:translateX(100%);transition:transform .22s ease;
 z-index:21;overflow-y:auto;padding:26px}
.zt-panel.open{transform:translateX(0)}
.zt-panel-close{position:absolute;top:18px;right:18px;cursor:pointer;border:1px solid var(--line);
 background:transparent;color:var(--ink);border-radius:8px;width:30px;height:30px;font-size:16px;
 line-height:1}
.zt-panel h2{font-size:19px;margin:0 34px 20px 0;text-wrap:balance}
.zt-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:14px;
 border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:20px}
.zt-fact{display:flex;flex-direction:column;gap:3px}
.zt-fact-l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.zt-fact-v{font-size:14px;font-weight:600}
.zt-result{display:flex;align-items:center;gap:10px;margin-bottom:20px;padding-bottom:20px;
 border-bottom:1px solid var(--line)}
.zt-result b{font-size:15px}
.zt-panel h4{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);
 margin:0 0 8px}
.zt-panel section{margin-bottom:20px}
.zt-panel p{font-size:13.5px;line-height:1.65;margin:0;color:var(--ink)}
.zt-panel ul{margin:0;padding-left:18px;font-size:13.5px;line-height:1.65}
.zt-panel ul li{margin:5px 0}
"""

_ZT_SCRIPT = """
function ztRows(scope){return document.querySelectorAll('tr.zt-row[data-scope="'+scope+'"]');}
function ztActiveChips(scope,key){
  var sel='.zt-chip.active[data-scope="'+scope+'"][data-key="'+key+'"]';
  return Array.prototype.map.call(document.querySelectorAll(sel), function(c){return c.dataset.val;});
}
function ztApply(scope){
  var risks=ztActiveChips(scope,'risk'), statuses=ztActiveChips(scope,'status');
  var searchEl=document.querySelector('.zt-search[data-scope="'+scope+'"]');
  var q=searchEl?searchEl.value.trim().toLowerCase():'';
  ztRows(scope).forEach(function(row){
    var okRisk=risks.length===0||risks.indexOf(row.dataset.risk)>-1;
    var okStatus=statuses.length===0||statuses.indexOf(row.dataset.status)>-1;
    var okSearch=!q||row.dataset.name.indexOf(q)>-1;
    row.style.display=(okRisk&&okStatus&&okSearch)?'':'none';
  });
}
function ztChip(btn){btn.classList.toggle('active');ztApply(btn.dataset.scope);}
function ztSearch(input){ztApply(input.dataset.scope);}
function ztOpen(row){
  var d=JSON.parse(row.getAttribute('data-detail'));
  document.getElementById('zt-title').textContent=d.name;
  var factsEl=document.getElementById('zt-facts');factsEl.innerHTML='';
  d.facts.forEach(function(f){
    var wrap=document.createElement('div');wrap.className='zt-fact';
    var l=document.createElement('span');l.className='zt-fact-l';l.textContent=f[0];
    var v=document.createElement('span');v.className='zt-fact-v';v.textContent=f[1];
    wrap.appendChild(l);wrap.appendChild(v);factsEl.appendChild(wrap);
  });
  var pill=document.getElementById('zt-result-pill');
  pill.textContent=d.status_label;pill.style.setProperty('--pc',d.status_color);
  document.getElementById('zt-result-line').textContent=d.result_line;
  document.getElementById('zt-checked').textContent=d.what_checked;
  var remEl=document.getElementById('zt-remediation');remEl.innerHTML='';
  d.remediation.forEach(function(r){var li=document.createElement('li');li.textContent=r;remEl.appendChild(li);});
  document.getElementById('zt-overlay').classList.add('open');
  document.getElementById('zt-panel').classList.add('open');
}
function ztClose(){
  document.getElementById('zt-overlay').classList.remove('open');
  document.getElementById('zt-panel').classList.remove('open');
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')ztClose();});
"""


def html_string(result: dict, tenant_id: str = "", now=None) -> str:
    a = assessment(result, now)
    exec_ = a["executive"]
    sev = exec_.get("findings_by_severity", {})
    donut = _donut([
        ("Yüksek", sev.get("high", 0), _SEV["high"]),
        ("Orta", sev.get("medium", 0), _SEV["medium"]),
        ("Düşük", sev.get("low", 0), _SEV["low"]),
        ("Bilgi", sev.get("info", 0), _SEV["info"]),
    ], center_label="Bulgu")
    legend = "".join(
        f'<div><span class="dot" style="background:{_SEV[k]}"></span>{lbl} '
        f'<b style="margin-left:auto">{sev.get(k, 0)}</b></div>'
        for k, lbl in (("high", "Yüksek"), ("medium", "Orta"), ("low", "Düşük"), ("info", "Bilgi")))

    tiles = "".join([
        f'<div class="card tile{" high" if exec_.get("apps_with_sensitive_data") else ""}">'
        f'<span class="n">{_esc(exec_.get("apps_with_sensitive_data", 0))}</span>'
        f'<span class="l">Hassas veri paylaşan app</span></div>',
        f'<div class="card tile"><span class="n">{_esc(exec_.get("total_affected_users", 0))}</span>'
        f'<span class="l">Etkilenen kullanıcı</span></div>',
        f'<div class="card tile"><span class="n">{_esc(exec_.get("total_blocked", 0))}</span>'
        f'<span class="l">Engellenen (DLP)</span></div>',
        f'<div class="card tile{" high" if exec_.get("high_severity_findings") else ""}">'
        f'<span class="n">{_esc(exec_.get("high_severity_findings", 0))}</span>'
        f'<span class="l">Yüksek önem bulgu</span></div>',
    ])

    nav = "".join(
        f'<a class="navlink" href="#{href}">{label}</a>'
        for href, label in (("coverage", "Coverage"), ("agents", "Agents"), ("traffic", "Traffic"),
                            ("exposure", "Exposure"), ("findings", "Findings"), ("gaps", "Gaps")))

    agent365_items = _agent365_items(a["agent365_packages"]["packages"])
    identity_items = _identity_items(a["agent_identities"]["identities"])
    shadow_items = _shadow_items(a["shadow_ai_usage"]["applications"])
    exposure_items = _exposure_items(a["sensitive_exposure"])
    finding_items = _finding_items(a["findings"])

    quick = "".join([
        f'<a class="card kpi" href="#coverage"><span class="n">{exec_["connectors_connected"]}/{exec_["connectors_total"]}</span>'
        f'<span class="l">Bağlı veri kaynağı</span></a>',
        f'<a class="card kpi" href="#agents"><span class="n">{len(agent365_items) + len(identity_items)}</span>'
        f'<span class="l">Agent (365 + Identity)</span></a>',
        f'<a class="card kpi" href="#traffic"><span class="n">{len(shadow_items)}</span>'
        f'<span class="l">Shadow AI uygulaması</span></a>',
        f'<a class="card kpi high" href="#exposure"><span class="n">{len(exposure_items)}</span>'
        f'<span class="l">Hassas veri exposure</span></a>',
    ])

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI-SPM — Microsoft AI Data Sources Assessment</title>
<style>{CSS}{_ZT_CSS}</style></head><body>
<header>{_MS_LOGO_SVG}<h1>AI-SPM · Microsoft AI Data Sources</h1>
<nav class="tabs">{nav}</nav>
<div class="spacer"></div><div class="tenant">{_esc(tenant_id)}</div></header>
<main>
<div class="hero">
  <div class="card">
    <h3>Kaynak Durumu</h3>
    <div class="tenant-facts">
      <b>Tenant</b><span>{_esc(tenant_id) or "—"}</span>
      <b>Bağlı kaynak</b><span>{exec_["connectors_connected"]}/{exec_["connectors_total"]}</span>
      <b>Eşleşen varlık</b><span>{_esc(exec_.get("matched_to_inventory", 0))}/{_esc(exec_.get("total_apps", 0))}</span>
      <b>Üretildi</b><span>{_esc(a["_generated_at"])[:19].replace("T", " ")} UTC</span>
    </div>
  </div>
  <div class="tiles">{tiles}</div>
  <div class="card">
    <h3>Bulgu Dağılımı</h3>
    <div class="summary">{donut}<div class="legend">{legend}</div></div>
  </div>
</div>
<div class="kpi-grid" style="margin-top:16px">{quick}</div>

<div class="card" style="margin-top:16px" id="coverage"><h3>1-2. Veri kaynağı coverage</h3>
{_coverage_html(a["data_source_coverage"])}</div>

{_zt_section("agents", "4-5. Agent Envanteri — Entra Agent Identities", "Owner/sponsor/izin ataması assessment sonucu olarak değerlendirilir", identity_items, "Entra Agent Identity keşfedilmedi.")}
{_zt_section("agent365", "5. Agent Envanteri — Agent 365 Paketleri", "Deployment kapsamı ve korelasyon durumu assessment sonucu olarak değerlendirilir", agent365_items, "Agent 365 paketi keşfedilmedi.")}
{_zt_section("traffic", "6. Shadow AI Uygulama Keşfi &amp; Trafik", "Defender for Cloud Apps — onay durumu ve kullanım hacmi assessment sonucu olarak değerlendirilir", shadow_items, "Shadow AI uygulaması keşfedilmedi (veya kaynak bağlı değil).")}

<div class="card" style="margin-top:16px" id="interactions"><h3>7. Purview — Son Hassas Etkileşimler / Trafik</h3>
{_interactions_table(a["sensitive_interactions"]["sample"])}</div>

{_zt_section("exposure", "3. Applications with Sensitive Data Exposure", "Hassas veri paylaşımı olan uygulamalar — DLP sonucu assessment olarak değerlendirilir", exposure_items, "Hassas veri paylaşımı tespit edilmedi (veya kaynaklar bağlı değil).")}
{_zt_section("findings", "8. Bulgular", "Her bulgu bir başarısız (failed) assessment kontrolü olarak listelenir", finding_items, "Bulgu yok.")}

<div class="card" style="margin-top:16px" id="gaps"><h3>15. Bilinen eksikler / API sınırları</h3>
<ul class="na">{"".join(f"<li>{_esc(g)}</li>" for g in a["known_gaps"])}</ul></div>
<div class="foot">AI-SPM — Microsoft AI Data Sources · connectors_report.assessment()</div>
</main>

<div class="zt-overlay" id="zt-overlay" onclick="ztClose()"></div>
<aside class="zt-panel" id="zt-panel" role="dialog" aria-label="Detay">
  <button class="zt-panel-close" onclick="ztClose()" aria-label="Kapat">&times;</button>
  <h2 id="zt-title"></h2>
  <div class="zt-facts" id="zt-facts"></div>
  <div class="zt-result">
    <span>Test result →</span>
    <span class="zt-pill" id="zt-result-pill"></span>
    <span id="zt-result-line" style="color:var(--muted);font-size:13px"></span>
  </div>
  <section><h4>What was checked</h4><p id="zt-checked"></p></section>
  <section><h4>Remediation action</h4><ul id="zt-remediation"></ul></section>
</aside>
<script>{_ZT_SCRIPT}</script>
</body></html>"""


def write_html(result: dict, path: str, tenant_id: str = "") -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(result, tenant_id))
