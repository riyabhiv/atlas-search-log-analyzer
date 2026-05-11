"""End-to-end integration test: synthetic log + CSV → analyze() → render_html().

Validates the full pipeline by hand-crafting a tiny log file with one example
of each opportunity category, plus one CSV with a known text index and a
known duplicate/unused pair. Then asserts the analyzer:

  * Skips NETWORK + admin.* lines.
  * Aggregates duplicate query hashes (R1 appears twice → 1 shape, count=2).
  * Detects every opportunity category.
  * Renders HTML containing the expected sections, severity tags, and
    catalog-derived field names.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from indexes import load_catalog
from main import analyze, render_html


FIXTURES = Path(__file__).parent / "fixtures"
LOG = FIXTURES / "synthetic.log"
CSV = FIXTURES / "indexes.csv"


@pytest.fixture(scope="module")
def result():
    catalog = load_catalog(CSV)
    return analyze(LOG, catalog=catalog), catalog


@pytest.fixture(scope="module")
def html(result):
    res, catalog = result
    # Build a minimal argparse-like Namespace
    class _Args:
        pass
    return render_html(res, LOG, _Args(), catalog=catalog)


# ---------------------------------------------------------------------------
# Analyzer-level assertions
# ---------------------------------------------------------------------------

class TestAnalyzerCounts:
    def test_total_lines_includes_blank_and_malformed(self, result):
        res, _ = result
        # 8 non-blank lines in fixture: 1 NETWORK + 6 valid slow-query + 1 malformed
        assert res.total_lines == 8

    def test_parsed_lines_excludes_malformed(self, result):
        res, _ = result
        # 1 line is "not a valid json" → 1 parse error
        assert res.parse_errors == 1
        assert res.parsed_lines == 7

    def test_slow_query_lines(self, result):
        res, _ = result
        # 6 'Slow query' events total (one of them is admin.*, but still found)
        assert res.slow_query_lines == 6

    def test_admin_namespace_skipped(self, result):
        res, _ = result
        # 1 slow-query event was on admin.system.users → skipped
        assert res.skipped_namespace == 1
        assert res.inspected_events == 5

    def test_aggregates_by_query_hash(self, result):
        res, _ = result
        # R1 appears twice → 1 shape with count=2
        # OR1, T1, RG1 each appear once → 3 more shapes
        # Total = 4 distinct shapes
        assert len(res.shapes) == 4
        shape_by_hash = {s.query_hash: s for s in res.shapes.values()}
        assert shape_by_hash["R1"].count == 2

    def test_namespaces_counted(self, result):
        res, _ = result
        # MyApp.Users (1 shape, count=2) + MyApp.Products + MyApp.Orders (2 shapes)
        assert res.namespaces["MyApp.Users"] == 2  # 2 events
        assert res.namespaces["MyApp.Products"] == 1
        assert res.namespaces["MyApp.Orders"] == 2


class TestDetection:
    def test_regex_case_insensitive_shape_tagged_leading_wildcard(self, result):
        res, _ = result
        shape = next(s for s in res.shapes.values() if s.query_hash == "R1")
        assert "leading_wildcard" in shape.categories
        assert shape.severity == "high"

    def test_or_shape_tagged_or_multi_field(self, result):
        res, _ = result
        shape = next(s for s in res.shapes.values() if s.query_hash == "OR1")
        assert "or_multi_field" in shape.categories

    def test_text_shape_tagged_text(self, result):
        res, _ = result
        shape = next(s for s in res.shapes.values() if s.query_hash == "T1")
        assert "text" in shape.categories

    def test_range_shape_not_an_opportunity(self, result):
        res, _ = result
        shape = next(s for s in res.shapes.values() if s.query_hash == "RG1")
        # No text-style opportunities for a pure range+equality on a date
        assert "text" not in shape.categories
        assert "regex" not in shape.categories
        assert "or_multi_field" not in shape.categories


class TestCatalogEnrichment:
    def test_text_shape_resolves_to_real_fields(self, result):
        res, _ = result
        shape = next(s for s in res.shapes.values() if s.query_hash == "T1")
        # OrdersTextIdx has weights: {Notes:1, ShipTo.Address:1}
        assert "<TEXT_INDEXED_FIELD>" not in shape.profile.text_fields
        assert {"Notes", "ShipTo.Address"} <= shape.profile.text_fields


# ---------------------------------------------------------------------------
# HTML output assertions
# ---------------------------------------------------------------------------

class TestHtmlOutput:
    def test_well_formed_doctype(self, html):
        assert html.startswith("<!doctype html>")
        assert "</html>" in html

    def test_summary_section(self, html):
        assert 'id="summary"' in html
        assert "Total log lines" in html

    def test_opportunities_section(self, html):
        assert 'id="opps"' in html
        assert "Atlas Search Opportunities" in html

    def test_drop_candidates_section_present(self, html):
        # Catalog supplied → section appears
        assert 'id="drops"' in html
        assert "Drop Candidates" in html

    def test_index_inventory_section_present(self, html):
        assert 'id="indexes"' in html
        assert "Index Inventory" in html

    def test_high_severity_pill_rendered(self, html):
        # We had leading_wildcard + or_multi_field + text → at least one HIGH
        assert "HIGH:" in html

    def test_namespace_table_shows_real_namespaces(self, html):
        assert "MyApp.Users" in html
        assert "MyApp.Orders" in html

    def test_resolved_text_fields_in_html(self, html):
        # Should see real weighted fields, not the placeholder
        assert "<TEXT_INDEXED_FIELD>" not in html
        assert "Notes" in html
        assert "ShipTo.Address" in html

    def test_drop_candidate_DupCreatedAtIdx_shown(self, html):
        assert "DupCreatedAtIdx" in html
        # Should be tagged in inventory and drop sections
        assert "UnusedIdx" in html

    def test_id_index_not_in_drop_candidates(self, html):
        # _id_ appears in inventory but not flagged as a drop candidate.
        # Check that the drop section doesn't list "_id_" as a row.
        import re
        m = re.search(r'id="drops".*?</section>', html, re.S)
        assert m
        drop_html = m.group(0)
        # The Drop Candidates table specifically shouldn't have _id_
        # (it appears elsewhere, e.g. inventory)
        assert "_id_" not in drop_html

    def test_recommendation_block_renders(self, html):
        assert "recommendation" in html
        assert "Suggested Atlas Search migration" in html

    def test_replaces_existing_indexes_block(self, html):
        # For the regex-on-Email shape, we should list EmailIdx as covered
        assert "Existing indexes potentially replaced" in html
        assert "EmailIdx" in html


class TestNoCatalogPath:
    """Confirm analyzer + report work when no CSV is supplied."""

    def test_analyze_without_catalog(self):
        res = analyze(LOG)  # no catalog
        assert len(res.shapes) == 4

    def test_render_html_without_catalog(self):
        res = analyze(LOG)

        class _Args:
            pass
        html = render_html(res, LOG, _Args())   # no catalog
        # No drop/inventory sections — but no crash
        assert 'id="drops"' not in html
        assert 'id="indexes"' not in html
        # Opportunities still rendered
        assert 'id="opps"' in html
        # Placeholder remains since catalog wasn't there to resolve it
        assert "&lt;TEXT_INDEXED_FIELD&gt;" in html or "<TEXT_INDEXED_FIELD>" in html
