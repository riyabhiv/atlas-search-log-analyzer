"""Tests for the detect() function — the rule engine that tags query shapes."""

from __future__ import annotations

import pytest

from main import QueryShape, detect, extract_event


def _new_shape(ns: str = "MyApp.Users") -> QueryShape:
    return QueryShape(query_hash="X", plan_cache_key="Y", namespace=ns, op_type="command")


# ---------------------------------------------------------------------------
# Category tagging
# ---------------------------------------------------------------------------

class TestCategoryTagging:
    def test_text_query_tags_text(self, slow_query_text_aggregate):
        s = _new_shape("FalconFlexTripsSvcProd.Task")
        detect(extract_event(slow_query_text_aggregate), s)
        assert "text" in s.categories

    def test_text_query_promotes_to_high_severity(self, slow_query_text_aggregate):
        s = _new_shape("FalconFlexTripsSvcProd.Task")
        detect(extract_event(slow_query_text_aggregate), s)
        assert s.severity == "high"

    def test_text_placeholder_substituted(self, slow_query_text_aggregate):
        # $text in filter — no real field name available; we use a placeholder
        s = _new_shape("FalconFlexTripsSvcProd.Task")
        detect(extract_event(slow_query_text_aggregate), s)
        assert "<TEXT_INDEXED_FIELD>" in s.profile.text_fields

    def test_fts_planSummary_tags_fts_index_alone(self):
        # planSummary alone, with no $text in filter (theoretical case)
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"someStringField": "abc"},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None,
            "plan_summary": 'IXSCAN { _fts: "text", _ftsx: 1 }',
            "keys_examined": 100, "docs_returned": 1,
        }
        s = _new_shape()
        detect(ev, s)
        assert "fts_index" in s.categories

    def test_regex_basic_tags_regex_only(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"name": {"$regex": "widget"}},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None, "plan_summary": "IXSCAN { name: 1 }",
            "keys_examined": 10, "docs_returned": 10,
        }
        s = _new_shape()
        detect(ev, s)
        assert "regex" in s.categories
        assert "leading_wildcard" not in s.categories
        assert s.severity == "medium"

    def test_regex_leading_wildcard_tags_leading_wildcard(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"name": {"$regex": ".*widget"}},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None, "plan_summary": "COLLSCAN",
            "keys_examined": 0, "docs_returned": 1,
        }
        s = _new_shape()
        detect(ev, s)
        assert "leading_wildcard" in s.categories
        assert s.severity == "high"

    def test_regex_case_insensitive_promotes_to_leading_wildcard(self, slow_query_regex_case_insens):
        s = _new_shape("MyApp.Users")
        detect(extract_event(slow_query_regex_case_insens), s)
        # Has $options:i — promoted to leading_wildcard
        assert "leading_wildcard" in s.categories

    def test_or_multi_field_tags_searchbar(self, slow_query_or_searchbar):
        s = _new_shape("MyApp.Products")
        detect(extract_event(slow_query_or_searchbar), s)
        assert "or_multi_field" in s.categories
        # Severity should be high
        assert s.severity == "high"

    def test_collscan_on_strings_tags_collscan_string(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"Status": "PAID"},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None, "plan_summary": "COLLSCAN",
            "keys_examined": 0, "docs_returned": 1,
        }
        s = _new_shape()
        detect(ev, s)
        assert "collscan_string" in s.categories

    def test_collscan_without_string_filter_does_not_tag(self, slow_query_find_collscan):
        # Empty filter — even though plan is COLLSCAN, no string fields touched
        s = _new_shape("FalconFlexTripsSvcProd.RelocationTask")
        detect(extract_event(slow_query_find_collscan), s)
        assert "collscan_string" not in s.categories

    def test_collation_strength_2_tags_case_insensitive(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"name": "alice"},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": {"locale": "en", "strength": 2},
            "plan_summary": "IXSCAN", "keys_examined": 1, "docs_returned": 1,
        }
        s = _new_shape()
        detect(ev, s)
        assert "case_insensitive" in s.categories

    def test_low_selectivity_tags_when_threshold_crossed(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"name": "alice"},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None,
            "plan_summary": "IXSCAN { name: 1 }",
            "keys_examined": 5000, "docs_returned": 10,    # ratio = 500
        }
        s = _new_shape()
        detect(ev, s)
        assert "low_selectivity" in s.categories

    def test_low_selectivity_does_not_tag_below_threshold(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"name": "alice"},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None,
            "plan_summary": "IXSCAN", "keys_examined": 500, "docs_returned": 50,
        }
        s = _new_shape()
        detect(ev, s)
        assert "low_selectivity" not in s.categories

    def test_range_only_does_not_trigger_text_opportunities(self, slow_query_with_range):
        # Should NOT flag $text/regex/or — only collscan_string if applicable
        s = _new_shape("MyApp.Orders")
        detect(extract_event(slow_query_with_range), s)
        # Status is a string equality; no COLLSCAN here -> shouldn't tag collscan_string
        # Should not tag any text-style opportunity
        assert "text" not in s.categories
        assert "regex" not in s.categories
        assert "or_multi_field" not in s.categories


# ---------------------------------------------------------------------------
# Profile attachment
# ---------------------------------------------------------------------------

class TestProfileAttachment:
    def test_detect_attaches_profile(self, slow_query_text_aggregate):
        s = _new_shape("FalconFlexTripsSvcProd.Task")
        detect(extract_event(slow_query_text_aggregate), s)
        assert s.profile is not None
        assert s.profile.text_query == '"(Reverse)"'

    def test_reasons_populated(self, slow_query_text_aggregate):
        s = _new_shape("FalconFlexTripsSvcProd.Task")
        detect(extract_event(slow_query_text_aggregate), s)
        assert any("$text" in r for r in s.reasons)
