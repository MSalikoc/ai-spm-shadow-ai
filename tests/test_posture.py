"""Tenant posture score and the analytical cards built on top of the chart library."""
import report


def _app(name, level, score, users=10, consent="Principal", app_perms=(), scopes=()):
    return {"display_name": name, "vendor": "V", "risk_level": level, "risk_score": score,
            "user_count": users, "consent_type": consent, "verified_publisher": True,
            "third_party": True, "first_party_microsoft": False,
            "scopes": list(scopes), "delegated_permissions": [],
            "application_permissions": [{"resource": "Microsoft Graph", "permission": p}
                                        for p in app_perms],
            "has_app_only_access": bool(app_perms), "reasons": ["r"], "remediation": ["m"]}


def _counts(apps):
    return {lv: sum(1 for a in apps if a["risk_level"] == lv)
            for lv in ("Critical", "High", "Medium", "Low")}


def test_clean_tenant_scores_zero():
    assert report._posture_score([], _counts([])) == 0


def test_score_rises_with_severity_not_with_headcount():
    """Twenty Low findings must not out-score two Criticals."""
    many_low = [_app(f"L{i}", "Low", 5) for i in range(20)]
    two_crit = [_app("C1", "Critical", 90), _app("C2", "Critical", 88)]
    assert (report._posture_score(two_crit, _counts(two_crit))
            > report._posture_score(many_low, _counts(many_low)))


def test_a_long_tail_of_low_findings_cannot_dilute_criticals():
    crit = [_app("C1", "Critical", 90)]
    crit_plus_tail = crit + [_app(f"L{i}", "Low", 4) for i in range(30)]
    assert (report._posture_score(crit_plus_tail, _counts(crit_plus_tail))
            >= report._posture_score(crit, _counts(crit)))


def test_score_saturates_instead_of_pinning_at_one_hundred():
    """
    A straight weighted sum clipped at 100 pins any mid-sized estate at exactly 100, so
    getting worse and getting better look identical. The curve has to keep moving.
    """
    bad = [_app(f"C{i}", "Critical", 95) for i in range(9)]
    worse = [_app(f"C{i}", "Critical", 95) for i in range(30)]
    s_bad = report._posture_score(bad, _counts(bad))
    s_worse = report._posture_score(worse, _counts(worse))
    assert s_bad < 100 and s_worse < 100
    assert s_worse > s_bad


def test_score_is_monotonic_as_findings_accumulate():
    seen = []
    for n in range(0, 24, 3):
        apps = [_app(f"C{i}", "Critical", 90) for i in range(n)]
        seen.append(report._posture_score(apps, _counts(apps)))
    assert seen == sorted(seen)


def test_admin_consent_and_app_only_access_push_the_score_up():
    plain = [_app("A", "Medium", 40)]
    org_wide = [_app("A", "Medium", 40, consent="AllPrincipals")]
    unattended = [_app("A", "Medium", 40, app_perms=["Directory.ReadWrite.All"])]
    base = report._posture_score(plain, _counts(plain))
    assert report._posture_score(org_wide, _counts(org_wide)) > base
    assert report._posture_score(unattended, _counts(unattended)) > base


def test_breakdown_shows_the_arithmetic_rather_than_a_bare_number():
    apps = [_app("A", "Critical", 90, consent="AllPrincipals")]
    out = report._posture_breakdown(apps, _counts(apps))
    assert "Critical findings" in out
    assert "Org-wide admin consent" in out
    assert "Exposure points" in out


def test_breakdown_is_honest_when_nothing_contributes():
    assert "Nothing contributing" in report._posture_breakdown([], _counts([]))


# --- the analytical cards ---------------------------------------------------
def test_triage_chart_sizes_dots_by_total_permissions_held():
    apps = [_app("Wide", "Critical", 90, scopes=["mail.read", "files.read.all"],
                 app_perms=["Directory.Read.All"])]
    svg = report._triage_chart(apps)
    assert "3 permissions" in svg          # 2 delegated + 1 app-only


def test_permission_heatmap_only_charts_sensitive_overlap():
    trivial = [_app("A", "Low", 5, scopes=["user.read", "openid"])]
    assert "viz-empty" in report._permission_heatmap(trivial)

    sensitive = [_app("A", "Critical", 90, scopes=["mail.read", "files.readwrite.all"]),
                 _app("B", "High", 60, scopes=["mail.read"])]
    out = report._permission_heatmap(sensitive)
    assert "mail.read" in out and "--viz-seq-" in out


def test_vendor_treemap_folds_the_tail_rather_than_inventing_a_ninth_color():
    apps = []
    for i in range(11):
        a = _app(f"App{i}", "Low", 5)
        a["vendor"] = f"Vendor {i}"
        apps.append(a)
    out = report._vendor_treemap(apps, top=7)
    assert "Other (4 vendors)" in out
    assert "--viz-cat-8" in out            # the fold uses the next slot, never a wrap


def test_dashboard_renders_every_new_analytical_card():
    apps = [_app("A", "Critical", 90, users=300, consent="AllPrincipals",
                 scopes=["mail.read", "files.readwrite.all"], app_perms=["Directory.Read.All"]),
            _app("B", "Low", 10, users=2, scopes=["user.read"])]
    doc = report.html_string(apps, "tenant-1")
    assert "Where to start" in doc
    assert "Tenant AI posture" in doc
    assert "Sensitive permission concentration" in doc
    assert "Estate share by vendor" in doc
    assert "Exposure points" in doc
