"""Analytical charts on the AI Data Sources dashboard."""
import charts
import connectors_report as cr


def test_direction_chart_orders_worst_outcome_first():
    """Largest-first would bury a single 'allowed despite DLP' under bulk observations."""
    out = cr._direction_chart({"OBSERVED": 90, "BLOCKED": 40, "ALLOWED": 1, "ACCESSED": 5})
    order = [out.index(lbl) for lbl in ("Allowed despite DLP", "Accessed org data",
                                        "Observed", "Blocked by DLP")]
    assert order == sorted(order)


def test_direction_uses_the_status_scale_not_categorical_slots():
    """Blocked is the good outcome; a categorical green beside it reads as the same thing."""
    assert cr._DIRECTION_COLOR["BLOCKED"] == charts.SEVERITY["Low"]
    assert cr._DIRECTION_COLOR["ALLOWED"] == charts.SEVERITY["Critical"]
    assert cr._DIRECTION_COLOR["UPLOADED"] == charts.SEVERITY["High"]
    greens = [d for d, c in cr._DIRECTION_COLOR.items() if c == charts.SEVERITY["Low"]]
    assert greens == ["BLOCKED"]          # exactly one direction reads as "good"


def test_direction_labels_fit_the_bar_label_column():
    assert all(len(v) <= 26 for v in cr._DIRECTION_LABEL.values())


def test_direction_chart_is_honest_when_there_is_nothing_to_show():
    assert "empty" in cr._direction_chart({})
    assert "empty" in cr._direction_chart({"BLOCKED": 0})


def test_mdca_risk_is_inverted_because_low_means_risky_there():
    """Defender scores 0-10 with LOW meaning risky — the inverse of every other score."""
    assert cr._mdca_risk_level(1) == "Critical"
    assert cr._mdca_risk_level(4) == "High"
    assert cr._mdca_risk_level(6) == "Medium"
    assert cr._mdca_risk_level(9) == "Low"
    assert cr._mdca_risk_level(None) == "Low"       # unknown never invents a severity


def test_shadow_scatter_plots_a_risky_app_high_not_low():
    apps = [{"display_name": "Risky", "risk_score": 1, "users": 100, "uploaded_bytes": 5 << 20},
            {"display_name": "Safe", "risk_score": 9, "users": 100, "uploaded_bytes": 1 << 20}]
    svg = cr._shadow_risk_scatter(apps)
    assert "Risky — risk 90/100" in svg
    assert "Safe — risk 10/100" in svg


def test_sit_chart_folds_the_tail_instead_of_inventing_colors():
    dist = {f"SIT {i}": 12 - i for i in range(12)}
    out = cr._sit_chart(dist, top=8)
    assert "Other (4 types)" in out
    assert "--viz-cat-8" in out


def test_sit_chart_folds_the_smallest_even_if_the_input_is_unordered():
    dist = {"tiny": 1, "huge": 500, "small": 2, "big": 300}
    out = cr._sit_chart(dist, top=2)
    assert "Other (2 types)" in out
    assert out.index("huge") < out.index("big")


def test_traffic_chart_skips_apps_with_no_upload_volume():
    apps = [{"display_name": "Quiet", "uploaded_bytes": 0, "risk_score": 5},
            {"display_name": "Chatty", "uploaded_bytes": 3 << 20, "risk_score": 2}]
    out = cr._shadow_traffic_chart(apps)
    assert "Chatty" in out and "Quiet" not in out


def test_analysis_cards_are_dropped_rather_than_drawn_empty():
    """A tenant without Purview should not get a page of blank frames."""
    nothing = cr._analysis_cards({"direction_analysis": {}, "sit_distribution": {}}, [])
    assert nothing == ""

    some = cr._analysis_cards({"direction_analysis": {"BLOCKED": 3}, "sit_distribution": {}}, [])
    assert "What happened to sensitive data" in some
    assert "Sensitive information types" not in some


def test_dashboard_renders_the_analysis_cards_end_to_end(monkeypatch):
    import pipeline
    from test_connectors_report import MegaFakeGraph

    for flag in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS",
                 "ENABLE_PURVIEW_AUDIT", "ENABLE_PREVIEW_CONNECTORS"):
        monkeypatch.setenv(flag, "true")
    monkeypatch.delenv("PURVIEW_DSPM_IMPORT_PATH", raising=False)

    doc = cr.html_string(pipeline.run_connectors(MegaFakeGraph()), "t")
    assert "What happened to sensitive data" in doc
    assert "Shadow AI: reach against risk" in doc
    assert "--viz-cat-1" in doc            # the shared chart tokens are on the page
