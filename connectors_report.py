"""
Microsoft AI Data Sources — birleşik assessment/rapor (Adım 7).

`report.py` (mevcut Entra/OAuth dashboard'u) HİÇ DEĞİŞTİRİLMEDİ; bu modül tamamen ayrı,
standalone bir sayfa üretir (aynı CSS/tema diliyle — `report.CSS` içe aktarılır, kopyalanmaz;
tab-switching JS deseni de report.py'den ilham alınarak — kopyalanarak, import edilmeden —
yeniden kurulur). Girdi `pipeline.run_connectors()`'ın döndürdüğü sonuç sözlüğü
(assets/coverage/health/counts/profiles/portfolio) — connector'lar env-flag ile kapalıysa
bu modül hiç çağrılmaz.

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

HTML görünümü (html_string), Microsoft'un Zero Trust Assessment aracındaki desenle çok
sayfalı bir dashboard kurar:
  - Overview   : hero (tenant/KPI/bulgu donut) + akış diyagramları (Shadow AI ve Agent
                 Identity için) + estate genelinde en yüksek skorlu 5 madde.
  - Agents     : Agent 365 paketleri + Entra Agent Identities (assessment tablosu).
  - Shadow AI  : Defender/MDCA keşfedilen uygulamalar (kullanıcı/cihaz/IP SAYILARI ile —
                 bireysel kimlik listesi API'de yok, bkz. known_gaps).
  - Sensitive Data: hassas veri exposure tablosu + Purview etkileşim log'u.
  - Findings   : bulgular.
  - Gaps       : bilinen eksikler / API sınırları.
Her madde (agent/uygulama/bulgu) 0-100 ŞEFFAF RİSK SKORU alır — `scoring.py`'nin
"toplanan puan + gerekçe" felsefesiyle aynı: her puan bileşeni "+N — sebep" olarak
gösterilir, skor uydurulmaz. Satıra tıklayınca açılan panelde: facts → Risk Skoru +
gerekçe listesi → Result → What was checked → Remediation action.
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
    # NOT: "purview_dspm_import" bilerek burada YOK — dashboard coverage listesinde
    # gösterilmiyor. O bir gerçek connector değil, dosya-yolu tabanlı manuel bir
    # import adaptörü (bkz. connectors/purview_dspm_import.py): kendi başına her zaman
    # NOT_CONFIGURED görünür ve tek başına açılamaz (Kudu ile dosya yükleme gerektirir),
    # bu yüzden ekranda kafa karıştırmaması için gizlendi. `PURVIEW_DSPM_IMPORT_PATH`
    # env var'ı hâlâ çalışır — ileri seviye kullanıcılar için sessizce kullanılabilir
    # kalıyor, sadece coverage/gaps listesinde satır olarak görünmüyor.
}

_SOURCE_LABEL = {
    "AGENT_365": "Agent 365", "ENTRA_AGENT_ID": "Entra Agent ID",
    "DEFENDER_CLOUD_APPS": "Defender for Cloud Apps", "PURVIEW_AUDIT": "Purview Audit",
    "PURVIEW_DSPM_EXPORT": "Purview DSPM", "ENTRA_APPS": "Entra OAuth (klasik)",
}


def _sources_label(sources) -> str:
    return ", ".join(_SOURCE_LABEL.get(s, s) for s in (sources or [])) or "—"


def _fmt_names(names, limit=6) -> str:
    names = [n for n in (names or []) if n]
    if not names:
        return "—"
    shown = names[:limit]
    rest = len(names) - len(shown)
    return ", ".join(shown) + (f" (+{rest} daha)" if rest > 0 else "")


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
        "app_only_perm_names": [p.get("resource_display_name") or p.get("resource_id") or "—"
                                for p in (a.get("agent_identity") or {}).get("application_permissions", [])],
        "delegated_perm_names": [s for g in (a.get("agent_identity") or {}).get("delegated_permissions", [])
                                 for s in (g.get("scopes") or [])],
        "blueprint_id": (a.get("related") or {}).get("blueprint_id")
                        or (a.get("agent_identity") or {}).get("blueprint_id"),
        "entra_app_id": (a.get("external_ids") or {}).get("entra_app_id"),
        "sources": a.get("sources") or [],
        "correlation_confidence": a.get("correlation_confidence"),
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
        "sources": a.get("sources") or [],
        "correlation_confidence": a.get("correlation_confidence"),
    } for a in agents]
    return {"metrics": m, "packages": rows}


def _shadow_ai(apps, m):
    rows = sorted([{
        "display_name": a.get("display_name"),
        "vendor": (a.get("mdca") or {}).get("vendor") or a.get("publisher") or "",
        "category": (a.get("mdca") or {}).get("category") or "",
        "sanctioned_state": (a.get("mdca") or {}).get("sanctioned_state"),
        "users": (a.get("mdca") or {}).get("users", 0),
        "devices": (a.get("mdca") or {}).get("devices", 0),
        "ip_addresses": (a.get("mdca") or {}).get("ip_addresses", 0),
        "transactions": (a.get("mdca") or {}).get("transactions", 0),
        "uploaded_bytes": (a.get("mdca") or {}).get("uploaded_bytes", 0),
        "downloaded_bytes": (a.get("mdca") or {}).get("downloaded_bytes", 0),
        "risk_score": (a.get("mdca") or {}).get("risk_score"),
        "data_sensitivity": (a.get("mdca") or {}).get("data_sensitivity"),
        "last_seen": a.get("last_seen"),
    } for a in apps], key=lambda r: r["uploaded_bytes"] + r["downloaded_bytes"], reverse=True)
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
    gaps.append("Defender for Cloud Apps (aggregatedAppsDetails) yalnızca kullanıcı/cihaz/IP "
               "SAYISI verir — bireysel kullanıcı/cihaz/IP kimliği bu API'de YOK; bu yüzden "
               "'hangi kullanıcı/cihaz' sorusu yalnızca Purview etkileşimleri (gerçek kullanıcı "
               "kimliği taşır) üzerinden cevaplanabilir.")
    return gaps


# ---------- JSON çıktı ----------
def json_string(result: dict, now=None) -> str:
    return json.dumps(assessment(result, now), ensure_ascii=False, indent=2, default=str)


# ---------- ortak HTML yardımcıları ----------
_SEV = {"high": "#c0392b", "medium": "#b8860b", "low": "#2e8b57", "info": "#6b7280"}
_RISK_LABEL = {"high": "Yüksek", "medium": "Orta", "low": "Düşük", "info": "Bilgi"}
_RISK_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}  # tablo sıralaması için


def _risk_tier(score):
    """Skor → risk kademesi. Tek doğruluk kaynağı: risk_label HER ZAMAN score'dan türetilir."""
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


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
def _donut(segments, size=170, stroke=26, center_label="Bulgu"):
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


def _flow_diagram(columns, flows, width=520, height=210, node_w=10):
    """
    Bağımlılıksız (D3 yok), el yapımı "akış" (Sankey-tarzı) diyagram — Microsoft'un
    Zero Trust Assessment aracındaki boru-temalı grafiklerle aynı fikir.
    columns: [[(node_id, label, color, value), ...], ...] — bitişik kolonlar arası akış olur.
    flows: [(from_id, to_id, value), ...] — yalnızca bitişik kolonlar arası desteklenir.
    """
    n_cols = len(columns)
    if n_cols < 2 or not any(columns):
        return '<div class="empty">Veri yok</div>'
    col_gap = (width - node_w * n_cols) / max(1, n_cols - 1)
    pad_y, gap_between = 10, 6
    usable_h = height - 2 * pad_y

    positions = {}
    for ci, col in enumerate(columns):
        total = sum(v for _, _, _, v in col) or 1
        avail = usable_h - gap_between * max(0, len(col) - 1)
        y = pad_y
        for nid, label, color, value in col:
            h = max(2.0, avail * value / total)
            positions[nid] = {"col": ci, "y0": y, "y1": y + h, "color": color,
                              "label": label, "value": value}
            y += h + gap_between

    svg = [f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
          f'role="img" class="flow" preserveAspectRatio="xMidYMid meet">']
    out_used, in_used = {}, {}
    for fid, tid, value in flows:
        if fid not in positions or tid not in positions:
            continue
        f_pos, t_pos = positions[fid], positions[tid]
        fx = f_pos["col"] * (node_w + col_gap) + node_w
        tx = t_pos["col"] * (node_w + col_gap)
        f_span = (f_pos["y1"] - f_pos["y0"])
        t_span = (t_pos["y1"] - t_pos["y0"])
        f_h = f_span * (value / f_pos["value"]) if f_pos["value"] else 0
        t_h = t_span * (value / t_pos["value"]) if t_pos["value"] else 0
        fy = f_pos["y0"] + out_used.get(fid, 0)
        ty = t_pos["y0"] + in_used.get(tid, 0)
        out_used[fid] = out_used.get(fid, 0) + f_h
        in_used[tid] = in_used.get(tid, 0) + t_h
        midx = (fx + tx) / 2
        path = (f"M{fx:.1f},{fy:.1f} C{midx:.1f},{fy:.1f} {midx:.1f},{ty:.1f} {tx:.1f},{ty:.1f} "
               f"L{tx:.1f},{ty + t_h:.1f} C{midx:.1f},{ty + t_h:.1f} {midx:.1f},{fy + f_h:.1f} "
               f"{fx:.1f},{fy + f_h:.1f} Z")
        svg.append(f'<path d="{path}" fill="{f_pos["color"]}" opacity="0.42"/>')

    for nid, pos in positions.items():
        x = pos["col"] * (node_w + col_gap)
        h = max(1.0, pos["y1"] - pos["y0"])
        svg.append(f'<rect x="{x:.1f}" y="{pos["y0"]:.1f}" width="{node_w}" height="{h:.1f}" '
                  f'fill="{pos["color"]}" rx="2"/>')
        ly = (pos["y0"] + pos["y1"]) / 2
        if pos["col"] == 0:
            anchor, tx_label = "start", x + node_w + 6
        elif pos["col"] == n_cols - 1:
            anchor, tx_label = "end", x - 6
        else:
            anchor, tx_label = "middle", x + node_w / 2
        svg.append(f'<text x="{tx_label:.1f}" y="{ly:.1f}" dy="4" text-anchor="{anchor}" '
                  f'class="flow-label">{_esc(pos["label"])} ({pos["value"]})</text>')
    svg.append("</svg>")
    return "".join(svg)


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
# yan panel (facts → Risk Skoru+gerekçe → Result → What was checked → Remediation).
# Skor 0-100, `scoring.py`'nin "toplanan puan + gerekçe" felsefesiyle: her puan
# bileşeni ayrı bir gerekçe cümlesiyle gelir, risk_label HER ZAMAN score'dan türetilir
# (bkz. _risk_tier) — "45 diyorsa neye göre 45?" sorusunun cevabı panelde satır satır.
# ==================================================================================
def _item(item_id, name, score, reasons, status_label, status_color,
         facts, result_line, what_checked, remediation, bucket=None):
    score = max(0, min(100, score))
    risk = _risk_tier(score)
    return {
        "id": item_id, "name": name, "bucket": bucket,
        "score": score, "risk_key": risk,
        "risk_label": _RISK_LABEL[risk], "risk_color": _SEV[risk],
        "reasons": [f"+{p} — {r}" if p > 0 else r for p, r in reasons],
        "status_label": status_label, "status_color": status_color,
        "facts": facts, "result_line": result_line, "what_checked": what_checked,
        "remediation": remediation if isinstance(remediation, list) else [remediation],
    }


def _agent365_items(packages):
    items = []
    for idx, p in enumerate(packages):
        name = p["display_name"]
        build_type = p["build_type"] or "bilinmiyor"
        deployed_to, available_to = p["deployed_to"] or "belirsiz", p["available_to"] or "belirsiz"
        available_all = available_to.strip().lower() in ("everyone", "all", "alltenant", "organization")
        correlated = bool(p.get("entra_app_id"))

        reasons = []
        if p["blocked"]:
            score = 5
            reasons.append((5, "Paket şu anda engellenmiş — aktif kullanılamıyor"))
            status_label, status_c, result_line = "Blocked", _SEV["high"], "Paket engellenmiş durumda."
        else:
            score = 0
            if available_all:
                score += 35
                reasons.append((35, "Deployment kapsamı 'everyone' — tüm organizasyona açık"))
            if not correlated:
                score += 30
                reasons.append((30, "Entra Agent ID ile korele değil — kimlik/izin görünürlüğü yok"))
            if build_type == "custom":
                score += 20
                reasons.append((20, "Custom (özel geliştirilmiş) build — daha az denetimden geçmiş olabilir"))
            if not reasons:
                reasons.append((0, "Belirgin bir risk sinyali yok"))
            if available_all and not correlated:
                status_label, status_c = "Investigate", _SEV["medium"]
                result_line = "Herkese açık ve Entra kimliğiyle korele değil."
            elif available_all:
                status_label, status_c = "Investigate", _SEV["medium"]
                result_line = "Herkese açık dağıtım."
            else:
                status_label, status_c = "Passed", _SEV["low"]
                result_line = "Kapsamı sınırlı, ek risk sinyali yok."

        what_checked = (
            f"{name}, Agent 365 kataloğunda kayıtlı bir {build_type} pakettir. "
            f"{deployed_to} kapsamına deploy edilmiş ve {available_to} kullanıcılara açık. "
            + ("Paket şu anda engellenmiş durumda. " if p["blocked"] else "Paket aktif ve engellenmemiş. ")
            + (f"Entra uygulaması ile korele: {p['entra_app_id']}."
               if correlated else "Herhangi bir Entra uygulamasıyla korele değil.")
        )
        remediation = []
        if not p["blocked"] and available_all and not correlated:
            remediation += ["Paketin kime açık olduğunu (deployment scope) daraltın.",
                          "Entra Agent ID ile korelasyon için ilgili appId'yi doğrulayın."]
        elif not p["blocked"] and available_all:
            remediation.append("Dağıtım kapsamının iş gerekliliğiyle örtüştüğünü doğrulayın.")
        elif p["blocked"]:
            remediation.append("Engelleme nedenini yayıncı/sorumlu ekiple doğrulayın; gerekmiyorsa kaldırmayın.")
        else:
            remediation.append("Ek aksiyon gerekmiyor; periyodik olarak gözden geçirin.")

        facts = [("Build Type", build_type), ("Deployment", deployed_to),
                ("Entra Korelasyonu", "Var" if correlated else "Yok"),
                ("Kaynaklar", _sources_label(p.get("sources"))),
                ("Korelasyon Güveni",
                 f"{p['correlation_confidence']}/100" if p.get("correlation_confidence") is not None else "—")]
        items.append(_item(f"agent365-{idx}", name, score, reasons, status_label, status_c,
                          facts, result_line, what_checked, remediation,
                          bucket="Blocked" if p["blocked"] else ("Everyone" if available_all else "Sınırlı")))
    return items


def _identity_items(identities):
    items = []
    for idx, i in enumerate(identities):
        name = i["display_name"]
        has_owner, has_sponsor = bool(i["owners"]), bool(i["sponsors"])
        perm_type = ("app-only + delegated" if i["app_only_perms"] and i["delegated_perms"]
                    else "yalnızca app-only" if i["app_only_perms"]
                    else "yalnızca delegated" if i["delegated_perms"] else "izin yok")

        reasons = []
        if not i["enabled"]:
            score = 5
            reasons.append((5, "Devre dışı (disabled) — aktif erişim riski yok"))
            status_label, status_c, result_line = "Disabled", _SEV["info"], "Devre dışı — aktif risk yok."
            bucket = "Disabled"
        else:
            score = 0
            if not has_owner:
                score += 35
                reasons.append((35, "Owner atanmamış"))
            if not has_sponsor:
                score += 20
                reasons.append((20, "Sponsor atanmamış"))
            if i["app_only_perms"] > 0:
                score += 15
                reasons.append((15, f"{i['app_only_perms']} app-only (kullanıcısız) izin var"))
            if not i.get("blueprint_id"):
                score += 10
                reasons.append((10, "Herhangi bir blueprint'e bağlı değil"))
            if not reasons:
                reasons.append((0, "Owner/sponsor/blueprint ataması tam"))
            if has_owner and has_sponsor:
                status_label, status_c, result_line = "Passed", _SEV["low"], "Owner ve sponsor atanmış."
            elif has_owner or has_sponsor:
                status_label, status_c, result_line = "Investigate", _SEV["medium"], "Owner veya sponsor eksik."
            else:
                status_label, status_c, result_line = "Failed", _SEV["high"], "Owner ve sponsor atanmamış."
            bucket = "Tam" if (has_owner and has_sponsor) else ("Kısmi" if (has_owner or has_sponsor) else "Yok")

        app_only_names = _fmt_names(i.get("app_only_perm_names"))
        delegated_names = _fmt_names(i.get("delegated_perm_names"))
        what_checked = (
            f"{name} " + ("etkin (enabled) durumda. " if i["enabled"] else "devre dışı (disabled) durumda. ")
            + f"Owner: {', '.join(i['owners']) if has_owner else 'atanmamış'}. "
            + f"Sponsor: {', '.join(i['sponsors']) if has_sponsor else 'atanmamış'}. "
            + f"{i['app_only_perms']} app-only ({app_only_names}) ve {i['delegated_perms']} delegated "
              f"({delegated_names}) izne sahip ({perm_type}). "
            + (f"Blueprint: {i['blueprint_id']}." if i.get("blueprint_id") else "Herhangi bir blueprint'e bağlı değil.")
            + f" Kaynaklar: {_sources_label(i.get('sources'))}."
        )
        remediation = []
        if i["enabled"] and not has_owner:
            remediation.append("Bu agent identity'sine bir owner atayın — hesap verebilirlik için gereklidir.")
        if i["enabled"] and not has_sponsor:
            remediation.append("Bir sponsor atayın (özellikle app-only izinleri varsa).")
        if not remediation:
            remediation.append("Ek aksiyon gerekmiyor.")

        facts = [("Owner", ", ".join(i["owners"]) or "—"), ("Sponsor", ", ".join(i["sponsors"]) or "—"),
                ("App-only İzinler", app_only_names), ("Delegated İzinler", delegated_names),
                ("Kaynaklar", _sources_label(i.get("sources"))),
                ("Korelasyon Güveni",
                 f"{i['correlation_confidence']}/100" if i.get("correlation_confidence") is not None else "—")]
        items.append(_item(f"identity-{idx}", name, score, reasons, status_label, status_c,
                          facts, result_line, what_checked, remediation, bucket=bucket))
    return items


def _shadow_items(apps, tenant_id=""):
    defender_url = (f"https://security.microsoft.com/cloudapps/discovery?tid={tenant_id}"
                    if tenant_id else None)
    items = []
    for idx, a in enumerate(apps):
        name, state = a["display_name"], a.get("sanctioned_state")
        reasons = []
        score = 0
        if state == "unsanctioned":
            score += 45
            reasons.append((45, "Onaysız (unsanctioned) uygulama"))
        elif state == "unreviewed":
            score += 25
            reasons.append((25, "Henüz gözden geçirilmedi (unreviewed)"))
        elif state == "sanctioned":
            reasons.append((0, "Kurumsal onaylı (sanctioned)"))
        else:
            score += 10
            reasons.append((10, "Onay durumu bilinmiyor"))
        if isinstance(a.get("risk_score"), int):
            mdca_pts = round((10 - a["risk_score"]) / 10 * 25)
            if mdca_pts:
                score += mdca_pts
                reasons.append((mdca_pts, f"MDCA risk skoru {a['risk_score']}/10 (düşük skor = yüksek risk)"))
        if a["users"] >= 20:
            score += 15
            reasons.append((15, f"{a['users']} kullanıcı bu uygulamayı kullanıyor (geniş yayılım)"))
        elif a["users"] >= 5:
            score += 8
            reasons.append((8, f"{a['users']} kullanıcı bu uygulamayı kullanıyor"))
        if a["uploaded_bytes"] >= 1_000_000:
            score += 10
            reasons.append((10, f"{a['uploaded_bytes']:,} bayt veri yüklendi (30g)"))

        result_line = {"unsanctioned": "Onaysız uygulama.", "sanctioned": "Kurumsal onaylı.",
                      "unreviewed": "Henüz gözden geçirilmedi."}.get(state, "Onay durumu belirsiz.")
        status_label, status_c = {
            "unsanctioned": ("Unsanctioned", _SEV["high"]), "unreviewed": ("Unreviewed", _SEV["medium"]),
            "sanctioned": ("Sanctioned", _SEV["low"]),
        }.get(state, ("Unreviewed", _SEV["info"]))

        what_checked = (
            f"{name}, Defender for Cloud Apps tarafından son 30 günde {a['users']} kullanıcı, "
            f"{a['devices']} cihaz ve {a['ip_addresses']} farklı IP adresinden gelen trafikle keşfedildi: "
            f"{a.get('transactions', 0):,} işlem, {a['uploaded_bytes']:,} bayt upload, "
            f"{a.get('downloaded_bytes', 0):,} bayt download. Onay durumu: {state or 'bilinmiyor'}. "
            + (f"MDCA risk skoru: {a['risk_score']}/10. " if a.get("risk_score") is not None else "")
            + f"Hassaslık durumu: {a.get('data_sensitivity') or 'bilinmiyor'} "
              "— Purview korelasyonu olmadan kesinleşmez. Not: bu sayılar TOPLAM'dır; MDCA "
              "aggregatedAppsDetails API'si bireysel kullanıcı/cihaz/IP kimliği vermez."
        )
        remediation = []
        if state == "unsanctioned":
            remediation += ["Uygulamayı Defender for Cloud Apps'te sanctioned veya blocked olarak işaretleyin.",
                          "Kullanıcıları onaylı bir alternatife yönlendirin."]
        elif state == "unreviewed":
            remediation.append("Uygulamayı gözden geçirip sanctioned/unsanctioned olarak sınıflandırın.")
        else:
            remediation.append("Ek aksiyon gerekmiyor; periyodik olarak trafiği izlemeye devam edin.")

        facts = [("Kullanıcı (30g)", a["users"]), ("Cihaz (30g)", a["devices"]),
                ("IP Adresi (30g)", a["ip_addresses"])]
        it = _item(f"shadow-{idx}", name, score, reasons, status_label, status_c,
                  facts, result_line, what_checked, remediation, bucket=state or "Bilinmiyor")
        # Defender for Cloud Apps "Discovered apps" grid ile aynı sütunlar (Risk score/Tag/
        # Traffic/Upload/Transactions/Users/IP addresses/Devices/Last seen) için ham veri.
        it["traffic"] = {
            "vendor": a.get("vendor") or "", "category": a.get("category") or "",
            "sanctioned_state": state, "risk_score": a.get("risk_score"),
            "users": a["users"], "devices": a["devices"], "ip_addresses": a["ip_addresses"],
            "transactions": a.get("transactions", 0),
            "uploaded_bytes": a["uploaded_bytes"], "downloaded_bytes": a.get("downloaded_bytes", 0),
            "last_seen": a.get("last_seen"),
            "defender_url": defender_url,
        }
        items.append(it)
    return items


def _exposure_items(rows):
    items = []
    for idx, p in enumerate(rows):
        s = p["sensitive_data_summary"]
        name = p["display_name"]
        dirs = ", ".join(f"{k}:{v}" for k, v in p["directions"].items() if v) or "yok"

        reasons = []
        score = 0
        if s["allowed"] > 0:
            score += 50
            reasons.append((50, f"{s['allowed']} hassas etkileşim DLP'ye rağmen izin verildi"))
        if s["blocked"] > 0:
            score += 10
            reasons.append((10, f"{s['blocked']} hassas etkileşim engellendi (pozitif kontrol)"))
        sit_pts = min(len(s["sit_types"]) * 8, 24)
        if sit_pts:
            score += sit_pts
            reasons.append((sit_pts, f"{len(s['sit_types'])} farklı hassas veri türü: {', '.join(s['sit_types'])}"))
        user_pts = min(p["affected_user_count"] * 3, 15)
        if user_pts:
            score += user_pts
            reasons.append((user_pts, f"{p['affected_user_count']} kullanıcı etkilendi"))
        if p.get("sanctioned_state") == "unsanctioned":
            score += 15
            reasons.append((15, "Onaysız (unsanctioned) uygulama"))
        if not reasons:
            reasons.append((0, "Belirgin bir risk sinyali yok"))

        if s["allowed"] > 0:
            status_label, status_c, result_line = "Failed", _SEV["high"], "DLP eşleşti ama izin verildi — inceleme gerekli."
        elif s["blocked"] > 0:
            status_label, status_c, result_line = "Passed", _SEV["low"], "Tüm hassas etkileşimler engellendi."
        else:
            status_label, status_c, result_line = "Investigate", _SEV["medium"], "Erişim var ama DLP eşleşmesi/engeli yok."

        what_checked = (
            f"{name} son 30 günde {s['window_30d']['sensitive']}/{s['window_30d']['interactions']} "
            f"hassas etkileşime sahip, {p['affected_user_count']} kullanıcıyı etkiliyor. "
            f"Veri türleri: {', '.join(s['sit_types']) or 'yok'}. Yön dağılımı: {dirs}. "
            f"{s['blocked']} engellendi, {s['allowed']} izin verildi."
        )
        remediation = [f["detail"] for f in p["findings"]] or ["Ek aksiyon gerekmiyor."]
        facts = [("Etkilenen Kullanıcı", p["affected_user_count"]),
                ("Hassas Etkileşim (30g)", s["window_30d"]["sensitive"]),
                ("Veri Türü Sayısı", len(s["sit_types"]))]
        items.append(_item(f"exposure-{idx}", name, score, reasons, status_label, status_c,
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
_FINDING_SCORE = {"high": 80, "medium": 50, "low": 25, "info": 10}


def _finding_items(findings):
    items = []
    for idx, f in enumerate(findings):
        sev = f["severity"] if f["severity"] in _SEV else "info"
        score = _FINDING_SCORE[sev]
        reasons = [(score, f["detail"])]
        status_label, status_c = ("Passed", _SEV["low"]) if sev == "info" else ("Failed", _SEV[sev])
        facts = [("Uygulama", f.get("app") or "—"), ("Etkilenen Kullanıcı", f.get("affected_users", "—")),
                ("Kaynak", "MDCA / Purview")]
        items.append(_item(
            f"finding-{idx}", f["type"].replace("_", " ").title(), score, reasons,
            status_label, status_c, facts, f["detail"], f["detail"],
            [_FINDING_REMEDIATION.get(f["type"], _DEFAULT_REMEDIATION)]))
    return items


def _fmt_bytes(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _mdca_risk_bar(score):
    """Defender for Cloud Apps'teki risk skoru barının aynısı — 0-10, 10=güvenli (yeşil)."""
    if score is None:
        return '<span style="color:var(--muted)">—</span>'
    color = "#2e8b57" if score >= 7 else ("#b8860b" if score >= 4 else "#c0392b")
    pct = max(5, score * 10)
    return (f'<div style="display:flex;align-items:center;gap:6px">'
           f'<div style="width:46px;height:7px;border-radius:4px;background:var(--track);overflow:hidden">'
           f'<div style="width:{pct}%;height:100%;background:{color}"></div></div>'
           f'<span class="c-num">{score}</span></div>')


def _sanction_pill(state):
    color = {"sanctioned": "#2e8b57", "unsanctioned": "#c0392b", "unreviewed": "#b8860b"}.get(state, "#6b7280")
    label = {"sanctioned": "Sanctioned", "unsanctioned": "Unsanctioned",
            "unreviewed": "Unreviewed"}.get(state, "—")
    return f'<span class="zt-pill" style="--pc:{color}">{_esc(label)}</span>'


def _zt_toolbar(section_id, items):
    risk_order = list(_RISK_LABEL.values())
    risks = sorted({it["risk_label"] for it in items}, key=lambda r: risk_order.index(r))
    statuses = sorted({it["status_label"] for it in items})
    risk_chips = "".join(
        f'<button class="zt-chip" data-scope="{section_id}" data-key="risk" data-val="{_esc(r)}" '
        f'onclick="ztChip(this)">{_esc(r)}</button>' for r in risks)
    status_chips = "".join(
        f'<button class="zt-chip" data-scope="{section_id}" data-key="status" data-val="{_esc(s)}" '
        f'onclick="ztChip(this)">{_esc(s)}</button>' for s in statuses)
    return (f'<div class="zt-toolbar">'
           f'<input class="zt-search" data-scope="{section_id}" placeholder="Ara..." oninput="ztSearch(this)">'
           f'<div class="zt-chips"><span class="zt-chip-label">Risk</span>{risk_chips}</div>'
           f'<div class="zt-chips"><span class="zt-chip-label">Status</span>{status_chips}</div>'
           f'</div>')


def _shadow_traffic_section(section_id, title, subtitle, items, empty_msg):
    """Defender for Cloud Apps'ın 'Discovered apps' grid'iyle aynı sütunlar: Risk score/Tag/
    Traffic/Upload/Transactions/Users/IP addresses/Devices/Last seen. Satıra tıklamak yine
    aynı assessment detay panelini (skor+gerekçe+remediation) açar."""
    if not items:
        return (f'<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>'
               f'<div class="empty">{_esc(empty_msg)}</div></div>')

    rows = []
    for it in sorted(items, key=lambda x: x["traffic"]["uploaded_bytes"] + x["traffic"]["downloaded_bytes"],
                     reverse=True):
        t = it["traffic"]
        total = t["uploaded_bytes"] + t["downloaded_bytes"]
        detail_json = html.escape(json.dumps(it), quote=True)
        last_seen = (t["last_seen"] or "")[:10] or "—"
        rows.append(
            f'<tr class="zt-row" data-scope="{section_id}" data-risk="{_esc(it["risk_label"])}" '
            f'data-status="{_esc(it["status_label"])}" data-name="{_esc(it["name"]).lower()}" '
            f"data-detail='{detail_json}' onclick=\"ztOpen(this)\">"
            f'<td data-sort="{_esc(it["name"]).lower()}"><div class="c-name">{_esc(it["name"])}</div>'
            f'<div style="font-size:11px;color:var(--muted)">{_esc(t["category"] or t["vendor"] or "—")}'
            + (f' &middot; <a href="{_esc(t["defender_url"])}" target="_blank" rel="noopener" '
               f'onclick="event.stopPropagation()" style="color:var(--accent)">Defender\'da aç ↗</a>'
               if t.get("defender_url") else "")
            + '</div></td>'
            f'<td data-sort="{t["risk_score"] if t["risk_score"] is not None else -1}">'
            f'{_mdca_risk_bar(t["risk_score"])}</td>'
            f'<td data-sort="{_esc(t["sanctioned_state"] or "").lower()}">'
            f'{_sanction_pill(t["sanctioned_state"])}</td>'
            f'<td class="c-num" data-sort="{total}">{_fmt_bytes(total)}</td>'
            f'<td class="c-num" data-sort="{t["uploaded_bytes"]}">{_fmt_bytes(t["uploaded_bytes"])}</td>'
            f'<td class="c-num" data-sort="{t["transactions"]}">{t["transactions"]:,}</td>'
            f'<td class="c-num" data-sort="{t["users"]}">{t["users"]}</td>'
            f'<td class="c-num" data-sort="{t["ip_addresses"]}">{t["ip_addresses"]}</td>'
            f'<td class="c-num" data-sort="{t["devices"]}">{t["devices"]}</td>'
            f'<td class="c-num" data-sort="{_esc(t["last_seen"] or "")}" style="white-space:nowrap">'
            f'{_esc(last_seen)}</td>'
            f"</tr>")

    headers = ["Uygulama", "Risk Score", "Tag", "Traffic", "Upload", "Transactions",
              "Users", "IP Addresses", "Devices", "Last Seen"]
    ths = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return f"""
<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>
<div class="c-subtitle">{_esc(subtitle)}</div>
{_zt_toolbar(section_id, items)}
<div class="c-tbl-wrap"><table class="c-tbl zt-table"><thead><tr>{ths}</tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</div>"""


def _zt_section(section_id, title, subtitle, items, empty_msg):
    if not items:
        return (f'<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>'
               f'<div class="empty">{_esc(empty_msg)}</div></div>')

    rows = []
    for it in sorted(items, key=lambda x: x["score"], reverse=True):
        detail_json = html.escape(json.dumps(it), quote=True)
        rows.append(
            f'<tr class="zt-row" data-scope="{section_id}" data-risk="{_esc(it["risk_label"])}" '
            f'data-status="{_esc(it["status_label"])}" data-name="{_esc(it["name"]).lower()}" '
            f"data-detail='{detail_json}' onclick=\"ztOpen(this)\">"
            f'<td class="c-name" data-sort="{_esc(it["name"]).lower()}">{_esc(it["name"])}</td>'
            f'<td class="c-num" data-sort="{it["score"]}"><b>{it["score"]}</b>/100</td>'
            f'<td data-sort="{_RISK_RANK[it["risk_key"]]}">'
            f'<span class="zt-pill" style="--pc:{it["risk_color"]}">{_esc(it["risk_label"])}</span></td>'
            f'<td data-sort="{_esc(it["status_label"]).lower()}">'
            f'<span class="zt-pill" style="--pc:{it["status_color"]}">{_esc(it["status_label"])}</span></td>'
            f'</tr>')

    return f"""
<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>
<div class="c-subtitle">{_esc(subtitle)}</div>
{_zt_toolbar(section_id, items)}
<div class="zt-tbl-wrap"><table class="zt-table">
<thead><tr><th>Ad</th><th>Skor</th><th>Risk</th><th>Status</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</div>"""


def _top_risks_html(all_items, n=5):
    top = sorted(all_items, key=lambda x: x["score"], reverse=True)[:n]
    if not top:
        return '<div class="empty">Madde yok.</div>'
    rows = "".join(
        f'<div class="zt-toprow" data-detail-ref="{it["id"]}">'
        f'<span class="zt-pill" style="--pc:{it["risk_color"]}">{it["score"]}</span>'
        f'<span class="c-name">{_esc(it["name"])}</span>'
        f'<span style="color:var(--muted);font-size:12px">{_esc(it["result_line"])}</span>'
        f'</div>' for it in top)
    return rows


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
header .navlink{cursor:pointer}
.flow-label{font-size:11px;fill:var(--ink)}
.flow-wrap{overflow-x:auto}
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
table.c-tbl thead th.zt-sortable,table.zt-table thead th.zt-sortable{cursor:pointer;user-select:none;
 white-space:nowrap}
table.c-tbl thead th.zt-sortable:hover,table.zt-table thead th.zt-sortable:hover{color:var(--ink)}
th.zt-sortable::after{content:"";margin-left:4px;opacity:.35}
th.sorted-asc::after{content:"▲";opacity:1}
th.sorted-desc::after{content:"▼";opacity:1}
table.zt-table tbody td{padding:10px 12px;border-bottom:1px solid var(--line)}
table.zt-table tbody tr:last-child td{border-bottom:none}
table.zt-table tbody tr{cursor:pointer;transition:background .12s}
table.zt-table tbody tr:hover{background:var(--track)}
.zt-pill{display:inline-block;background:var(--pc,#6b7280);color:#fff;font-size:11px;font-weight:700;
 padding:3px 10px;border-radius:999px}
.zt-toprow{display:flex;align-items:center;gap:12px;padding:9px 4px;border-bottom:1px solid var(--line);
 font-size:13px}
.zt-toprow:last-child{border-bottom:none}
.zt-overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);opacity:0;pointer-events:none;
 transition:opacity .18s;z-index:20}
.zt-overlay.open{opacity:1;pointer-events:auto}
.zt-panel{position:fixed;top:0;right:0;bottom:0;width:min(500px,92vw);background:var(--panel);
 box-shadow:-8px 0 30px rgba(0,0,0,.18);transform:translateX(100%);transition:transform .22s ease;
 z-index:21;overflow-y:auto;padding:26px}
.zt-panel.open{transform:translateX(0)}
.zt-panel-close{position:absolute;top:18px;right:18px;cursor:pointer;border:1px solid var(--line);
 background:transparent;color:var(--ink);border-radius:8px;width:30px;height:30px;font-size:16px;
 line-height:1}
.zt-panel h2{font-size:19px;margin:0 34px 20px 0;text-wrap:balance}
.zt-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:14px;
 border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:18px}
.zt-fact{display:flex;flex-direction:column;gap:3px}
.zt-fact-l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.zt-fact-v{font-size:14px;font-weight:600}
.zt-score{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.zt-score-num{font-size:30px;font-weight:700;font-family:"Cascadia Code",Consolas,ui-monospace,monospace;
 min-width:60px}
.zt-score-bar{flex:1;height:10px;border-radius:6px;background:var(--track);overflow:hidden}
.zt-score-fill{height:100%;border-radius:6px;transition:width .2s}
.zt-result{display:flex;align-items:center;gap:10px;margin:18px 0;padding-bottom:18px;
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
(function(){
function showTab(n){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('active',t.getAttribute('data-tab')===n);});
  document.querySelectorAll('.navlink').forEach(function(x){x.classList.toggle('active',x.getAttribute('data-tab')===n);});
  window.scrollTo(0,0);
}
document.querySelectorAll('.navlink').forEach(function(l){l.onclick=function(){showTab(l.getAttribute('data-tab'));};});
document.querySelectorAll('[data-goto]').forEach(function(c){c.onclick=function(e){e.preventDefault();showTab(c.getAttribute('data-goto'));};});
window.ztGoto = showTab;
var coreLink=document.getElementById('coreDashboardLink');
if(coreLink){
  if(location.pathname.indexOf('/api/')===0){
    coreLink.href='/api/report'+(location.search||'');
  }else{
    coreLink.remove();
  }
}
})();
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
  document.getElementById('zt-score-num').textContent=d.score+'/100';
  var fill=document.getElementById('zt-score-fill');
  fill.style.width=d.score+'%';fill.style.background=d.risk_color;
  var reasonsEl=document.getElementById('zt-reasons');reasonsEl.innerHTML='';
  d.reasons.forEach(function(r){var li=document.createElement('li');li.textContent=r;reasonsEl.appendChild(li);});
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
function ztSortTable(th){
  var table=th.closest('table');
  if(!table)return;
  var tbody=table.querySelector('tbody');
  if(!tbody)return;
  var ths=Array.prototype.slice.call(th.parentNode.children);
  var idx=ths.indexOf(th);
  var dir=th.classList.contains('sorted-asc')?'desc':'asc';
  ths.forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});
  th.classList.add(dir==='asc'?'sorted-asc':'sorted-desc');
  var rows=Array.prototype.slice.call(tbody.rows);
  rows.sort(function(a,b){
    var ac=a.cells[idx],bc=b.cells[idx];
    var av=ac?(ac.dataset.sort!==undefined?ac.dataset.sort:ac.textContent.trim().toLowerCase()):'';
    var bv=bc?(bc.dataset.sort!==undefined?bc.dataset.sort:bc.textContent.trim().toLowerCase()):'';
    var an=parseFloat(av),bn=parseFloat(bv);
    var cmp=(!isNaN(an)&&!isNaN(bn)&&av!==''&&bv!=='')?(an-bn):String(av).localeCompare(String(bv));
    return dir==='asc'?cmp:-cmp;
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}
document.querySelectorAll('table.zt-table thead th, table.c-tbl thead th').forEach(function(th){
  th.classList.add('zt-sortable');
  th.onclick=function(){ztSortTable(th);};
});
"""


def _shadow_flow(shadow_items):
    if not shadow_items:
        return None
    bucket_color = {"unsanctioned": "#c0392b", "sanctioned": "#2e8b57", "unreviewed": "#b8860b"}
    buckets, risk_by_bucket = {}, {}
    for it in shadow_items:
        b = it["bucket"]
        buckets[b] = buckets.get(b, 0) + 1
        risk_by_bucket.setdefault(b, {})
        risk_by_bucket[b][it["risk_key"]] = risk_by_bucket[b].get(it["risk_key"], 0) + 1

    col1 = [("src", "Keşfedilen Uygulamalar", "#5f6b7a", len(shadow_items))]
    col2 = [(f"b:{b}", b, bucket_color.get(b, "#5f6b7a"), c) for b, c in buckets.items()]
    risk_totals = {}
    for rc in risk_by_bucket.values():
        for rk, c in rc.items():
            risk_totals[rk] = risk_totals.get(rk, 0) + c
    col3 = [(f"r:{rk}", _RISK_LABEL[rk], _SEV[rk], c) for rk, c in risk_totals.items()]

    flows = [("src", f"b:{b}", c) for b, c in buckets.items()]
    for b, rc in risk_by_bucket.items():
        for rk, c in rc.items():
            flows.append((f"b:{b}", f"r:{rk}", c))
    return _flow_diagram([col1, col2, col3], flows)


def _identity_flow(identity_items):
    if not identity_items:
        return None
    bucket_color = {"Tam": "#2e8b57", "Kısmi": "#b8860b", "Yok": "#c0392b", "Disabled": "#6b7280"}
    buckets, risk_by_bucket = {}, {}
    for it in identity_items:
        b = it["bucket"]
        buckets[b] = buckets.get(b, 0) + 1
        risk_by_bucket.setdefault(b, {})
        risk_by_bucket[b][it["risk_key"]] = risk_by_bucket[b].get(it["risk_key"], 0) + 1

    col1 = [("src", "Agent Identities", "#5f6b7a", len(identity_items))]
    col2 = [(f"b:{b}", f"Owner/Sponsor: {b}", bucket_color.get(b, "#5f6b7a"), c) for b, c in buckets.items()]
    risk_totals = {}
    for rc in risk_by_bucket.values():
        for rk, c in rc.items():
            risk_totals[rk] = risk_totals.get(rk, 0) + c
    col3 = [(f"r:{rk}", _RISK_LABEL[rk], _SEV[rk], c) for rk, c in risk_totals.items()]

    flows = [("src", f"b:{b}", c) for b, c in buckets.items()]
    for b, rc in risk_by_bucket.items():
        for rk, c in rc.items():
            flows.append((f"b:{b}", f"r:{rk}", c))
    return _flow_diagram([col1, col2, col3], flows)


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
        f'<a class="navlink{" active" if t == "overview" else ""}" data-tab="{t}">{label}</a>'
        for t, label in (("overview", "Overview"), ("agents", "Agents"), ("shadow", "Shadow AI"),
                        ("sensitive", "Sensitive Data"), ("findings", "Findings"), ("gaps", "Gaps")))

    agent365_items = _agent365_items(a["agent365_packages"]["packages"])
    identity_items = _identity_items(a["agent_identities"]["identities"])
    shadow_items = _shadow_items(a["shadow_ai_usage"]["applications"], tenant_id)
    exposure_items = _exposure_items(a["sensitive_exposure"])
    finding_items = _finding_items(a["findings"])
    all_items = agent365_items + identity_items + shadow_items + exposure_items + finding_items

    quick = "".join([
        f'<a class="card kpi" data-goto="agents"><span class="n">{exec_["connectors_connected"]}/{exec_["connectors_total"]}</span>'
        f'<span class="l">Bağlı veri kaynağı</span></a>',
        f'<a class="card kpi" data-goto="agents"><span class="n">{len(agent365_items) + len(identity_items)}</span>'
        f'<span class="l">Agent (365 + Identity)</span></a>',
        f'<a class="card kpi" data-goto="shadow"><span class="n">{len(shadow_items)}</span>'
        f'<span class="l">Shadow AI uygulaması</span></a>',
        f'<a class="card kpi high" data-goto="sensitive"><span class="n">{len(exposure_items)}</span>'
        f'<span class="l">Hassas veri exposure</span></a>',
    ])

    shadow_flow = _shadow_flow(shadow_items)
    identity_flow = _identity_flow(identity_items)
    flow_cards = ""
    if shadow_flow or identity_flow:
        cells = []
        if shadow_flow:
            cells.append(f'<div class="card"><h3>Shadow AI: Onay Durumu → Risk Akışı</h3>'
                        f'<div class="flow-wrap">{shadow_flow}</div></div>')
        if identity_flow:
            cells.append(f'<div class="card"><h3>Agent Identity: Owner/Sponsor → Risk Akışı</h3>'
                        f'<div class="flow-wrap">{identity_flow}</div></div>')
        flow_cards = f'<div class="grid cols-2" style="margin-top:16px">{"".join(cells)}</div>'

    top_risks = _top_risks_html(all_items)

    overview = f"""
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
{flow_cards}
<div class="card" style="margin-top:16px"><h3>En Yüksek Riskli 5 Madde (tüm kaynaklar)</h3>
{top_risks}</div>
<div class="card" style="margin-top:16px"><h3>Veri Kaynağı Coverage</h3>
{_coverage_html(a["data_source_coverage"])}</div>"""

    agents_tab = (
        _zt_section("identities", "Entra Agent Identities",
                   "Owner/sponsor/izin ataması — skor: eksik atama arttıkça yükselir",
                   identity_items, "Entra Agent Identity keşfedilmedi.")
        + _zt_section("agent365", "Agent 365 Paketleri",
                     "Deployment kapsamı ve Entra korelasyonu — skor: geniş kapsam + korelasyon eksikliği",
                     agent365_items, "Agent 365 paketi keşfedilmedi."))

    shadow_tab = _shadow_traffic_section(
        "shadow", "Shadow AI — Discovered Apps",
        "Defender for Cloud Apps 'Discovered apps' görünümüyle aynı sütunlar — "
        "kullanıcı/cihaz/IP SAYILARI (bireysel kimlik listesi API'de yok — bkz. Gaps). "
        "Satıra tıklayınca risk skoru + gerekçesi + remediation paneli açılır.",
        shadow_items, "Shadow AI uygulaması keşfedilmedi (veya kaynak bağlı değil).")

    sensitive_tab = (
        _zt_section("exposure", "Applications with Sensitive Data Exposure",
                   "DLP sonucu (engellendi/izin verildi) ve veri türü çeşitliliği skoru belirler",
                   exposure_items, "Hassas veri paylaşımı tespit edilmedi (veya kaynaklar bağlı değil).")
        + f'<div class="card" style="margin-top:16px"><h3>Purview — Son Hassas Etkileşimler</h3>'
          f'{_interactions_table(a["sensitive_interactions"]["sample"])}</div>')

    findings_tab = _zt_section("findings", "Bulgular",
                              "Her bulgu bir başarısız (failed) assessment kontrolü olarak listelenir",
                              finding_items, "Bulgu yok.")

    gaps_tab = (f'<div class="card"><h3>Bilinen Eksikler / API Sınırları</h3>'
              f'<ul class="na">{"".join(f"<li>{_esc(g)}</li>" for g in a["known_gaps"])}</ul></div>')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI-SPM — Microsoft AI Data Sources Assessment</title>
<style>{CSS}{_ZT_CSS}</style></head><body>
<header>{_MS_LOGO_SVG}<h1>AI-SPM</h1>
<nav class="tabs">{nav}</nav>
<div class="spacer"></div><div class="tenant">{_esc(tenant_id)}</div>
<a id="coreDashboardLink" class="themebtn" href="#" style="display:inline-block;text-decoration:none;margin-left:10px" title="Core (OAuth-consent) dashboard'a git">&#8592; Core Dashboard</a>
</header>
<main>
<section class="tab active" data-tab="overview">{overview}</section>
<section class="tab" data-tab="agents">{agents_tab}</section>
<section class="tab" data-tab="shadow">{shadow_tab}</section>
<section class="tab" data-tab="sensitive">{sensitive_tab}</section>
<section class="tab" data-tab="findings">{findings_tab}</section>
<section class="tab" data-tab="gaps">{gaps_tab}</section>
<div class="foot">AI-SPM — Microsoft AI Data Sources · connectors_report.assessment()</div>
</main>

<div class="zt-overlay" id="zt-overlay" onclick="ztClose()"></div>
<aside class="zt-panel" id="zt-panel" role="dialog" aria-label="Detay">
  <button class="zt-panel-close" onclick="ztClose()" aria-label="Kapat">&times;</button>
  <h2 id="zt-title"></h2>
  <div class="zt-facts" id="zt-facts"></div>
  <h4>Risk Skoru</h4>
  <div class="zt-score"><span class="zt-score-num" id="zt-score-num"></span>
  <div class="zt-score-bar"><div class="zt-score-fill" id="zt-score-fill"></div></div></div>
  <h4>Neden bu skor?</h4>
  <ul id="zt-reasons"></ul>
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
