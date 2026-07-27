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


def _exposure_table(rows):
    trs = [
        f'<tr><td class="c-name">{_esc(p["display_name"])}</td>'
        f'<td>{_sanction_chip(p.get("sanctioned_state"))}</td>'
        f'<td class="c-num">{_esc(p["sensitive_data_summary"]["window_30d"]["sensitive"])}</td>'
        f'<td class="c-num">{_esc(p["affected_user_count"])}</td>'
        f'<td>{"".join(f"<span class=\'c-tag\'>{_esc(t)}</span>" for t in p["sensitive_data_summary"]["sit_types"][:3]) or "—"}</td>'
        f'<td class="c-num">{len(p["findings"])}</td></tr>' for p in rows]
    return _table(["Uygulama", "Onay durumu", "Hassas (30g)", "Etkilenen kullanıcı",
                  "Veri türleri", "Bulgu"], trs,
                 "Hassas veri paylaşımı tespit edilmedi (veya kaynaklar bağlı değil).")


def _sanction_chip(state):
    color = {"sanctioned": "#2e8b57", "unsanctioned": "#c0392b"}.get(state, "#6b7280")
    return f'<span class="c-chip" style="color:{color}">{_esc(state or "—")}</span>'


# ---------- klasik dashboard'un (report.py) görsel dilini yeniden kullanan yardımcılar ----------
# report.py'ye DOKUNULMUYOR — sadece aynı CSS (import edilen `CSS`) üzerine, aynı bileşen
# desenleriyle (donut/bars/kpi-grid/finding) kendi, bağımsız bir sayfa kuruyoruz.
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


# ---------- keşif: envanter (Agent 365 / Entra Agent ID / Shadow AI app'leri) ----------
def _agent365_table(packages):
    trs = [
        f'<tr><td class="c-name">{_esc(p["display_name"])}</td><td>{_esc(p["build_type"])}</td>'
        f'<td>{"🔴 evet" if p["blocked"] else "🟢 hayır"}</td>'
        f'<td>{_esc(p["available_to"])}</td><td>{_esc(p["deployed_to"])}</td>'
        f'<td>{_esc(p.get("entra_app_id")) if p.get("entra_app_id") else "<i>korele değil</i>"}</td></tr>'
        for p in packages]
    return _table(["Paket", "Build type", "Engelli mi", "Kime açık", "Nereye deploy",
                  "Entra App ID"], trs, "Agent 365 paketi keşfedilmedi.")


def _identities_table(identities):
    trs = []
    for i in identities:
        owners = ", ".join(i["owners"]) or "<i>owner yok</i>"
        sponsors = ", ".join(i["sponsors"]) or "<i>sponsor yok</i>"
        trs.append(
            f'<tr><td class="c-name">{_esc(i["display_name"])}</td>'
            f'<td>{"🟢 enabled" if i["enabled"] else "🔴 disabled"}</td>'
            f'<td>{owners}</td><td>{sponsors}</td>'
            f'<td class="c-num">{i["app_only_perms"]}</td><td class="c-num">{i["delegated_perms"]}</td>'
            f'<td>{_esc(i.get("blueprint_id")) if i.get("blueprint_id") else "<i>yok</i>"}</td></tr>')
    return _table(["Identity", "Durum", "Owner", "Sponsor", "App-only izin",
                  "Delegated izin", "Blueprint"], trs, "Entra Agent Identity keşfedilmedi.")


_SANCTION_COLOR = {"sanctioned": "#2e8b57", "unsanctioned": "#c0392b", "unreviewed": "#8b98a6"}


def _shadow_traffic_bars(apps):
    """Klasik dashboard'un `_bars()` deseniyle — kullanıcı sayısına göre trafik sıralaması."""
    if not apps:
        return '<div class="empty">Shadow AI uygulaması keşfedilmedi (veya kaynak bağlı değil).</div>'
    ranked = sorted(apps, key=lambda a: a["users"], reverse=True)
    rows = [
        (a["display_name"], f"{a.get('sanctioned_state') or '—'} · {a['uploaded_bytes']:,} B yüklendi",
         a["users"], _SANCTION_COLOR.get(a.get("sanctioned_state"), "#6b7280"))
        for a in ranked]
    return _bars(rows, max((a["users"] for a in apps), default=1))


def _inventory_html(a):
    return f"""
<div class="card" id="agents"><h3>4-5. Agent Envanteri — Agent 365 &amp; Entra Agent ID</h3>
<div class="c-subtitle">Agent 365 paketleri</div>{_agent365_table(a["agent365_packages"]["packages"])}
<div class="c-subtitle" style="margin-top:14px">Entra Agent Identities</div>
{_identities_table(a["agent_identities"]["identities"])}
</div>
<div class="card" style="margin-top:16px" id="traffic"><h3>6. Shadow AI Uygulama Keşfi &amp; Trafik</h3>
<div class="c-subtitle">Defender for Cloud Apps — kullanıcı sayısına göre (30g)</div>
{_shadow_traffic_bars(a["shadow_ai_usage"]["applications"])}
</div>"""


def _interactions_table(sample):
    trs = [
        f'<tr><td class="c-num">{_esc(i.get("timestamp"))}</td><td class="c-name">{_esc(i.get("app_host"))}</td>'
        f'<td>{_esc(i.get("user"))}</td><td><span class="c-tag">{_esc(i.get("direction"))}</span></td>'
        f'<td>{"".join(f"<span class=\'c-tag\'>{_esc(s)}</span>" for s in i.get("sits") or []) or "—"}</td></tr>'
        for i in sample]
    return _table(["Zaman", "Uygulama", "Kullanıcı", "Yön", "Veri türü"], trs,
                 "Purview'da hassas etkileşim yok (veya kaynak bağlı değil).")


# ---------- inceleme: uygulama/agent detayı (expandable) ----------
def _application_detail_html(rows):
    if not rows:
        return '<div class="empty">İncelenecek uygulama yok.</div>'
    parts = []
    for p in rows:
        s = p["sensitive_data_summary"]
        dirs = ", ".join(f"{k}:{v}" for k, v in p["directions"].items() if v) or "—"
        sits = ", ".join(s["sit_types"]) or "—"
        findings_html = "".join(
            f'<li><b style="color:{_SEV.get(f["severity"], "#6b7280")}">{_esc(f["severity"]).upper()}</b> '
            f'{_esc(f["detail"])}</li>' for f in p["findings"]) or "<li>Bulgu yok.</li>"
        parts.append(f"""<details class="c-detail"><summary><b>{_esc(p['display_name'])}</b>
<span class="c-tag">{_esc(p.get('sanctioned_state') or '—')}</span>
<span style="color:var(--muted)">{s['window_30d']['sensitive']} hassas / {s['window_30d']['interactions']} etkileşim (30g)</span></summary>
<div class="c-detail-body">
<div><b>Veri türleri:</b> {_esc(sits)}</div>
<div><b>Etiketler:</b> {_esc(", ".join(s["labels"]) or "—")}</div>
<div><b>Yön dağılımı:</b> {_esc(dirs)}</div>
<div><b>Engellenen / izin verilen:</b> {s['blocked']} / {s['allowed']}</div>
<div><b>Bulgular:</b><ul>{findings_html}</ul></div>
</div></details>""")
    return "".join(parts)


def _agent_detail_html(rows):
    if not rows:
        return '<div class="empty">İncelenecek agent identity yok.</div>'
    parts = []
    for i in rows:
        owners = ", ".join(o.get("upn") or o.get("display_name") or "—" for o in i["owners"]) or "yok"
        sponsors = ", ".join(o.get("upn") or o.get("display_name") or "—" for o in i["sponsors"]) or "yok"
        app_perms = ", ".join(p.get("resource_display_name") or "—" for p in i["application_permissions"]) or "yok"
        del_perms = ", ".join(s for p in i["delegated_permissions"] for s in p.get("scopes", [])) or "yok"
        groups = ", ".join(g.get("display_name") or "—" for g in i["group_memberships"]) or "yok"
        bp = (i.get("blueprint") or {}).get("display_name") or "yok"
        state = "🟢 enabled" if i["account_enabled"] else "🔴 disabled"
        parts.append(f"""<details class="c-detail"><summary><b>{_esc(i['display_name'])}</b>
<span style="color:var(--muted)">{state}</span></summary>
<div class="c-detail-body">
<div><b>Owner:</b> {_esc(owners)}</div>
<div><b>Sponsor:</b> {_esc(sponsors)}</div>
<div><b>App-only izinler:</b> {_esc(app_perms)}</div>
<div><b>Delegated izinler:</b> {_esc(del_perms)}</div>
<div><b>Grup üyelikleri:</b> {_esc(groups)}</div>
<div><b>Blueprint:</b> {_esc(bp)}</div>
</div></details>""")
    return "".join(parts)


_EXTRA_CSS = """
.c-subtitle{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;
 letter-spacing:.03em;margin:4px 0 8px}
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
.c-chip{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.02em}
.c-detail{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;overflow:hidden;
 background:var(--panel)}
.c-detail summary{padding:11px 15px;cursor:pointer;display:flex;gap:10px;align-items:center;
 list-style:none;font-size:13.5px}
.c-detail summary::-webkit-details-marker{display:none}
.c-detail-body{padding:0 15px 14px;font-size:13px;color:var(--ink);display:flex;
 flex-direction:column;gap:5px}
.c-detail-body b{color:var(--muted);font-weight:600}
.c-detail-body ul{margin:2px 0 0;padding-left:18px}
header .navlink{text-decoration:none}
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
                            ("exposure", "Exposure"), ("detail", "İnceleme"),
                            ("findings", "Findings"), ("gaps", "Gaps")))

    quick = "".join([
        f'<a class="card kpi" href="#coverage"><span class="n">{exec_["connectors_connected"]}/{exec_["connectors_total"]}</span>'
        f'<span class="l">Bağlı veri kaynağı</span></a>',
        f'<a class="card kpi" href="#agents"><span class="n">{len(a["agent365_packages"]["packages"]) + len(a["agent_identities"]["identities"])}</span>'
        f'<span class="l">Agent (365 + Identity)</span></a>',
        f'<a class="card kpi" href="#traffic"><span class="n">{len(a["shadow_ai_usage"]["applications"])}</span>'
        f'<span class="l">Shadow AI uygulaması</span></a>',
        f'<a class="card kpi high" href="#exposure"><span class="n">{len(a["sensitive_exposure"])}</span>'
        f'<span class="l">Hassas veri exposure</span></a>',
    ])

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI-SPM — Microsoft AI Data Sources Assessment</title>
<style>{CSS}{_EXTRA_CSS}</style></head><body>
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
{_inventory_html(a)}
<div class="card" style="margin-top:16px" id="interactions"><h3>7. Purview — Son Hassas Etkileşimler / Trafik</h3>
{_interactions_table(a["sensitive_interactions"]["sample"])}</div>
<div class="card" style="margin-top:16px" id="exposure"><h3>3. Applications with Sensitive Data Exposure</h3>
{_exposure_table(a["sensitive_exposure"])}</div>
<div class="card" style="margin-top:16px" id="detail"><h3>11. İnceleme — Uygulama Detayı</h3>
{_application_detail_html(a["application_detail"])}</div>
<div class="card" style="margin-top:16px"><h3>12. İnceleme — Agent Identity Detayı</h3>
{_agent_detail_html(a["agent_detail"])}</div>
<div class="card" style="margin-top:16px" id="findings"><h3>8. Bulgular</h3>{_findings_html(a["findings"])}</div>
<div class="card" style="margin-top:16px" id="gaps"><h3>15. Bilinen eksikler / API sınırları</h3>
<ul class="na">{"".join(f"<li>{_esc(g)}</li>" for g in a["known_gaps"])}</ul></div>
<div class="foot">AI-SPM — Microsoft AI Data Sources · connectors_report.assessment()</div>
</main></body></html>"""


def write_html(result: dict, path: str, tenant_id: str = "") -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(result, tenant_id))
