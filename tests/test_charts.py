"""Chart library — geometry, escaping, empty states, and the encoding rules."""
import re

import charts


def _paths(svg, tag):
    return re.findall(rf"<{tag}\b[^>]*>", svg)


# --- empty states never crash and never render a misleading chart ----------
def test_every_form_degrades_to_a_message_rather_than_an_empty_chart():
    assert "viz-empty" in charts.donut([])
    assert "viz-empty" in charts.hbar([])
    assert "viz-empty" in charts.stacked_bar([], ["a"], {})
    assert "viz-empty" in charts.timeseries([])
    assert "viz-empty" in charts.timeseries([0, 0, 0])
    assert "viz-empty" in charts.risk_scatter([])
    assert "viz-empty" in charts.heatmap([], [], [])
    assert "viz-empty" in charts.treemap([])


def test_donut_ignores_zero_and_negative_segments():
    svg = charts.donut([("A", 5, "#111"), ("B", 0, "#222"), ("C", -3, "#333")])
    assert svg.count("<circle") == 2          # the track plus one real segment
    assert "#222" not in svg and "#333" not in svg


# --- severity is a status scale, never carried by color alone -------------
def test_severity_levels_use_the_fixed_status_palette():
    assert charts.SEVERITY_ORDER == ["Critical", "High", "Medium", "Low"]
    assert charts.severity_color("Critical") == "#d03b3b"
    assert charts.severity_color("Low") == "#0ca30c"
    # An unknown level gets neutral ink, not a recycled severity hue.
    assert charts.severity_color("Bogus") not in charts.SEVERITY.values()


def test_severity_marks_always_carry_a_text_label():
    """Red/amber/green is hard to separate under CVD; the label is the mitigation."""
    rows = [("App A", "v", 90, charts.severity_color("Critical")),
            ("App B", "v", 40, charts.severity_color("Medium"))]
    svg = charts.hbar(rows)
    assert "App A" in svg and "App B" in svg
    assert ">90<" in svg and ">40<" in svg     # value is direct-labelled, not hue-only

    lg = charts.legend([(lv, charts.severity_color(lv), 3) for lv in charts.SEVERITY_ORDER])
    for level in charts.SEVERITY_ORDER:
        assert level in lg


# --- identity colors are assigned in fixed order, never cycled -------------
def test_categorical_slots_are_stable_and_do_not_wrap_past_eight():
    assert charts.cat(0) == "var(--viz-cat-1)"
    assert charts.cat(7) == "var(--viz-cat-8)"
    # A ninth series must not silently reuse slot 1 — callers fold it into "Other".
    assert charts.cat(8) == "var(--viz-cat-8)"
    assert charts.cat(99) == "var(--viz-cat-8)"


def test_both_theme_steps_are_defined_for_every_slot():
    assert len(charts.CATEGORICAL_LIGHT) == len(charts.CATEGORICAL_DARK)
    assert len(charts.SEQUENTIAL_LIGHT) == len(charts.SEQUENTIAL_DARK)
    for i in range(1, charts.CATEGORICAL_SLOTS + 1):
        assert f"--viz-cat-{i}:" in charts.CSS
    assert "prefers-color-scheme:dark" in charts.CSS
    assert "[data-theme=dark]" in charts.CSS and "[data-theme=light]" in charts.CSS


def test_sequential_ramp_maps_magnitude_monotonically():
    steps = [charts.seq(x / 10) for x in range(11)]
    nums = [int(re.search(r"seq-(\d+)", s).group(1)) for s in steps]
    assert nums == sorted(nums)                 # never goes backwards
    assert charts.seq(0) == "var(--viz-seq-1)"
    assert charts.seq(1.0) == f"var(--viz-seq-{len(charts.SEQUENTIAL_LIGHT)})"


# --- geometry --------------------------------------------------------------
def test_gauge_arc_never_sweeps_the_long_way_round():
    """A 180-degree gauge with large-arc-flag=1 draws a reflex arc — the 68 bug."""
    for score in (0, 10, 49, 51, 68, 99, 100):
        svg = charts.gauge(score)
        arcs = re.findall(r"A74,74 0 (\d) 1", svg)
        assert arcs and all(f == "0" for f in arcs), f"score {score} drew a reflex arc"


def test_gauge_clamps_out_of_range_scores():
    assert ">100<" in charts.gauge(140)
    assert ">0<" in charts.gauge(-20)
    assert 'width="210"' in charts.gauge(50)   # fixed size, so it cannot stretch


def test_gauge_band_matches_the_scoring_thresholds():
    assert "Critical" in charts.gauge(75) and "Critical" in charts.gauge(100)
    assert "High" in charts.gauge(50) and "High" in charts.gauge(74)
    assert "Medium" in charts.gauge(25) and "Low" in charts.gauge(24)


def test_hbar_scales_bars_against_the_largest_value():
    svg = charts.hbar([("Big", "", 100, "#111"), ("Half", "", 50, "#222")])
    widths = [float(w) for w in re.findall(r'width="([\d.]+)" height="18" rx="4" fill="#\w+"', svg)]
    assert len(widths) == 2
    assert abs(widths[0] / widths[1] - 2) < 0.05


def test_hbar_keeps_a_zero_value_visible_instead_of_drawing_nothing():
    svg = charts.hbar([("Some", "", 10, "#111"), ("None", "", 0, "#222")])
    assert "None" in svg and ">0<" in svg


def test_timeseries_axis_ticks_are_round_numbers():
    svg = charts.timeseries([3, 17, 42, 88])
    ticks = [t for t in re.findall(r'class="ax">([\d.km]+)</text>', svg)]
    assert "0" in ticks
    assert any(t in ticks for t in ("25", "20", "50"))


def test_timeseries_labels_the_endpoint_not_every_point():
    svg = charts.timeseries([1, 2, 3, 4, 5, 60], unit=" users")
    assert svg.count('class="val"') <= 2       # endpoint, plus at most one peak


def test_scatter_uses_a_log_x_axis_so_consent_counts_stay_comparable():
    pts = [("A", 50, 1, "Medium", 1), ("B", 50, 10, "Medium", 1),
           ("C", 50, 100, "Medium", 1), ("D", 50, 1000, "Medium", 1)]
    svg = charts.risk_scatter(pts)
    xs = [float(x) for x in re.findall(r'<circle cx="([\d.]+)"', svg)]
    gaps = [round(b - a) for a, b in zip(xs, xs[1:])]
    # Even decade spacing is the whole point of the log scale.
    assert max(gaps) - min(gaps) <= 2
    assert "log scale" in svg


def test_scatter_dot_area_tracks_permission_count():
    svg = charts.risk_scatter([("Few", 50, 10, "Low", 1), ("Many", 50, 10, "Low", 16)])
    radii = sorted(float(r) for r in re.findall(r'r="([\d.]+)"', svg))
    assert radii[1] > radii[0] * 1.5


def test_scatter_names_only_the_few_that_matter():
    pts = [(f"App {i}", i * 8, 10, "Medium", 2) for i in range(1, 12)]
    svg = charts.risk_scatter(pts)
    assert svg.count('class="val"') == 3


def test_heatmap_header_is_deep_enough_for_rotated_labels():
    svg = charts.heatmap(["r1"], ["A really long permission name"], [[5]])
    height = float(re.search(r'viewBox="0 0 [\d.]+ ([\d.]+)"', svg).group(1))
    ys = [float(y) for y in re.findall(r'<text x="[-\d.]+" y="([\d.]+)"', svg)]
    assert min(ys) > 0 and height > 60         # nothing pushed above the top edge


def test_heatmap_shades_by_magnitude_and_leaves_zero_on_the_track():
    svg = charts.heatmap(["a"], ["x", "y"], [[0, 9]])
    assert "var(--track)" in svg               # zero is absence, not a faint value
    assert "--viz-seq-" in svg


def test_treemap_areas_are_proportional_and_fill_the_canvas():
    items = [("A", 50, "#111"), ("B", 30, "#222"), ("C", 20, "#333")]
    svg = charts.treemap(items, width=400, height=200)
    rects = re.findall(r'<rect x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"', svg)
    areas = [float(w) * float(h) for _x, _y, w, h in rects]
    assert len(areas) == 3
    total = sum(areas)
    assert abs(areas[0] / total - 0.5) < 0.05
    assert abs(total - 400 * 200) / (400 * 200) < 0.08


def test_treemap_orders_tiles_largest_first():
    svg = charts.treemap([("small", 1, "#111"), ("big", 99, "#222")])
    assert svg.index("big") < svg.index("small")


def test_stacked_segments_are_separated_by_a_gap_not_an_outline():
    svg = charts.stacked_bar([("Row", {"a": 5, "b": 5})], ["a", "b"], {"a": "#111", "b": "#222"})
    assert "stroke" not in svg                 # a border around marks is the anti-pattern
    assert svg.count('class="mark"') == 2


# --- escaping --------------------------------------------------------------
def test_labels_from_tenant_data_are_escaped_everywhere():
    evil = '<script>alert("x")</script>'
    for svg in (charts.hbar([(evil, evil, 5, "#111")]),
                charts.donut([(evil, 5, "#111")]),
                charts.treemap([(evil, 5, "#111")]),
                charts.heatmap([evil], [evil], [[1]]),
                charts.risk_scatter([(evil, 50, 5, "Low", 1)]),
                charts.timeseries([1, 2], labels=[evil, evil]),
                charts.legend([(evil, "#111", 1)])):
        assert "<script>" not in svg
        assert "&lt;script&gt;" in svg


def test_every_mark_carries_a_hover_title():
    assert "<title>" in charts.donut([("A", 1, "#111")])
    assert "<title>" in charts.hbar([("A", "", 1, "#111")])
    assert "<title>" in charts.treemap([("A", 1, "#111")])
    assert "<title>" in charts.risk_scatter([("A", 1, 1, "Low", 1)])
    assert "<title>" in charts.heatmap(["r"], ["c"], [[1]])
    assert "<title>" in charts.timeseries([1, 2, 3])


def test_scatter_drops_a_name_that_would_land_on_another():
    """Top-scoring apps cluster in the same corner; three names stacked read as none."""
    clustered = [(f"Very Long App Name {i}", 100 - i, 500, "Critical", 4) for i in range(5)]
    svg = charts.risk_scatter(clustered)
    assert svg.count('class="val"') == 1

    spread = [("Low reach", 95, 2, "Critical", 4), ("Wide reach", 40, 900, "Medium", 4)]
    assert charts.risk_scatter(spread).count('class="val"') == 2


def test_scatter_keeps_top_scoring_dots_inside_the_plot():
    svg = charts.risk_scatter([("Maxed", 100, 500, "Critical", 30)])
    cy = float(re.search(r'<circle cx="[\d.]+" cy="([\d.]+)" r="([\d.]+)"', svg).group(1))
    r = float(re.search(r'<circle cx="[\d.]+" cy="[\d.]+" r="([\d.]+)"', svg).group(1))
    assert cy - r > 0          # dot is not sliced by the top edge
