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


# ---------- standalone HTML ----------
def _esc(s):
    return html.escape(str(s)) if s is not None else "—"


def _kpi(label, value, cls=""):
    return (f'<div class="kpi {cls}"><div class="n">{_esc(value)}</div>'
           f'<div class="l">{_esc(label)}</div></div>')


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


def _exposure_table(rows):
    if not rows:
        return '<div class="empty">Hassas veri paylaşımı tespit edilmedi (veya kaynaklar bağlı değil).</div>'
    trs = "".join(
        f'<tr><td>{_esc(p["display_name"])}</td><td>{_esc(p.get("sanctioned_state"))}</td>'
        f'<td>{_esc(p["sensitive_data_summary"]["window_30d"]["sensitive"])}</td>'
        f'<td>{_esc(p["affected_user_count"])}</td>'
        f'<td>{_esc(", ".join(p["sensitive_data_summary"]["sit_types"][:3]))}</td>'
        f'<td>{len(p["findings"])}</td></tr>' for p in rows)
    return (f'<table class="tbl"><thead><tr><th>Uygulama</th><th>Onay durumu</th>'
           f'<th>Hassas (30g)</th><th>Etkilenen kullanıcı</th><th>Veri türleri</th>'
           f'<th>Bulgu</th></tr></thead><tbody>{trs}</tbody></table>')


def _findings_html(findings):
    if not findings:
        return '<div class="empty">Bulgu yok.</div>'
    items = "".join(
        f'<div class="finding"><summary style="display:flex;gap:14px;padding:12px 16px">'
        f'<b style="color:{_SEV.get(f["severity"], "#6b7280")}">{_esc(f["severity"]).upper()}</b>'
        f'<span>{_esc(f["type"])}</span><span style="color:var(--muted)">{_esc(f["detail"])}</span>'
        f'</summary></div>' for f in findings)
    return items


_SEV = {"high": "#c0392b", "medium": "#b8860b", "low": "#2e8b57", "info": "#6b7280"}


def html_string(result: dict, tenant_id: str = "", now=None) -> str:
    a = assessment(result, now)
    exec_ = a["executive"]
    kpis = "".join([
        _kpi("Bağlı kaynak", f'{exec_["connectors_connected"]}/{exec_["connectors_total"]}'),
        _kpi("Hassas veri paylaşan app", exec_.get("apps_with_sensitive_data", 0), "high"),
        _kpi("Etkilenen kullanıcı", exec_.get("total_affected_users", 0)),
        _kpi("Engellenen (DLP)", exec_.get("total_blocked", 0)),
        _kpi("Yüksek önem bulgu", exec_.get("high_severity_findings", 0), "high"),
    ])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI-SPM — Microsoft AI Data Sources Assessment</title>
<style>{CSS}</style></head><body>
<header><div class="logo"></div><h1>AI-SPM — Microsoft AI Data Sources</h1>
<div class="spacer"></div><div class="tenant">{_esc(tenant_id)}</div></header>
<main>
<section class="grid cols-4" style="margin-bottom:16px">{kpis}</section>
<div class="card"><h3>1-2. Veri kaynağı coverage</h3>{_coverage_html(a["data_source_coverage"])}</div>
<div class="card" style="margin-top:16px"><h3>3. Applications with Sensitive Data Exposure</h3>
{_exposure_table(a["sensitive_exposure"])}</div>
<div class="card" style="margin-top:16px"><h3>8. Bulgular</h3>{_findings_html(a["findings"])}</div>
<div class="card" style="margin-top:16px"><h3>15. Bilinen eksikler / API sınırları</h3>
<ul class="na">{"".join(f"<li>{_esc(g)}</li>" for g in a["known_gaps"])}</ul></div>
</main></body></html>"""


def write_html(result: dict, path: str, tenant_id: str = "") -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(result, tenant_id))
