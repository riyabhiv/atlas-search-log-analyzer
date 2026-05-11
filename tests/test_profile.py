"""Tests for the structured QueryProfile builder (_classify_field_cond etc.)."""

from __future__ import annotations

import pytest

from main import _build_profile, _classify_field_cond, extract_event
from recommend import QueryProfile


# ---------------------------------------------------------------------------
# _classify_field_cond — per-condition role classification
# ---------------------------------------------------------------------------

class TestClassifyFieldCond:
    def setup_method(self):
        self.p = QueryProfile()

    def test_scalar_string_becomes_equality(self):
        _classify_field_cond(self.p, "Status", "PAID")
        assert self.p.equality_fields == {"Status": "PAID"}
        assert self.p.range_fields == set()

    def test_scalar_number_becomes_equality(self):
        _classify_field_cond(self.p, "StatusId", 1)
        assert self.p.equality_fields == {"StatusId": 1}

    def test_eq_operator_becomes_equality(self):
        _classify_field_cond(self.p, "Status", {"$eq": "PAID"})
        assert self.p.equality_fields == {"Status": "PAID"}

    def test_in_operator_becomes_equality_with_sample(self):
        _classify_field_cond(self.p, "Status", {"$in": ["PAID", "SHIPPED"]})
        # Stores first element as a representative sample
        assert self.p.equality_fields["Status"] == "PAID"

    def test_in_empty_does_nothing(self):
        _classify_field_cond(self.p, "Status", {"$in": []})
        assert self.p.equality_fields == {}

    def test_range_gte(self):
        _classify_field_cond(self.p, "CreatedAtUtc", {"$gte": {"$date": "2026-01-01"}})
        assert "CreatedAtUtc" in self.p.range_fields

    def test_range_lte(self):
        _classify_field_cond(self.p, "Price", {"$lte": 100})
        assert "Price" in self.p.range_fields

    def test_range_gt_lt(self):
        _classify_field_cond(self.p, "X", {"$gt": 1, "$lt": 10})
        assert "X" in self.p.range_fields

    def test_regex_without_leading_wildcard_goes_to_text(self):
        _classify_field_cond(self.p, "Name", {"$regex": "widget"})
        assert "Name" in self.p.text_fields
        assert "Name" not in self.p.autocomplete_fields
        assert self.p.regex_patterns == [("Name", "widget")]

    def test_regex_with_leading_wildcard_goes_to_autocomplete(self):
        _classify_field_cond(self.p, "Name", {"$regex": ".*foo"})
        assert "Name" in self.p.autocomplete_fields

    def test_regex_with_anchored_wildcard_also_autocomplete(self):
        _classify_field_cond(self.p, "Name", {"$regex": "^.*foo"})
        assert "Name" in self.p.autocomplete_fields

    def test_ne_is_ignored(self):
        # $ne has no Atlas Search equivalent — should not pollute roles
        _classify_field_cond(self.p, "Status", {"$ne": "DELETED"})
        assert self.p.equality_fields == {}
        assert self.p.range_fields == set()
        assert self.p.text_fields == set()

    def test_exists_is_ignored(self):
        _classify_field_cond(self.p, "X", {"$exists": True})
        assert self.p.equality_fields == {}


# ---------------------------------------------------------------------------
# _build_profile — end-to-end on the realistic fixtures
# ---------------------------------------------------------------------------

class TestBuildProfile:
    def test_text_aggregate_extracts_search_term(self, slow_query_text_aggregate):
        ev = extract_event(slow_query_text_aggregate)
        p = _build_profile(ev)
        assert p.text_query == '"(Reverse)"'
        # ExecutingCompanyId + StatusId end up in equality_fields
        assert p.equality_fields["ExecutingCompanyId"] == "61b0d247360a67f5f35da9cb"
        assert p.equality_fields["StatusId"] == 1

    def test_text_aggregate_extracts_sort_and_limit(self, slow_query_text_aggregate):
        ev = extract_event(slow_query_text_aggregate)
        p = _build_profile(ev)
        assert p.sort_fields == [("CreatedAtUtc", -1)]
        assert p.limit == 20000
        # skip is 0; we record 0 as None-ish — check it's falsy
        assert not p.skip

    def test_text_aggregate_op_and_collection(self, slow_query_text_aggregate):
        ev = extract_event(slow_query_text_aggregate)
        p = _build_profile(ev)
        assert p.collection == "Task"
        assert p.op_type == "command"

    def test_or_searchbar_collects_or_fields(self, slow_query_or_searchbar):
        ev = extract_event(slow_query_or_searchbar)
        p = _build_profile(ev)
        # Name + Description have regex; Sku is a string equality
        assert "Name" in p.or_text_fields
        assert "Description" in p.or_text_fields
        # Sku scalar equality inside $or is also captured as a text-like branch
        assert "Sku" in p.or_text_fields

    def test_range_filter(self, slow_query_with_range):
        ev = extract_event(slow_query_with_range)
        p = _build_profile(ev)
        assert "CreatedAtUtc" in p.range_fields
        # Status is a string equality
        assert p.equality_fields.get("Status") == "PAID"

    def test_regex_case_insensitive_sets_flag(self, slow_query_regex_case_insens):
        # _build_profile alone doesn't read $options i (that lives in detect),
        # but the regex pattern itself should be captured.
        ev = extract_event(slow_query_regex_case_insens)
        p = _build_profile(ev)
        assert any(f == "Email" for f, _ in p.regex_patterns)

    def test_collation_strength_sets_case_insensitive(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {}, "pipeline": None,
            "sort": None, "skip": None, "limit": None,
            "collation": {"locale": "en", "strength": 2},
        }
        p = _build_profile(ev)
        assert p.case_insensitive is True

    def test_collation_strength_3_does_not_set_flag(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {}, "pipeline": None,
            "sort": None, "skip": None, "limit": None,
            "collation": {"locale": "en", "strength": 3},
        }
        p = _build_profile(ev)
        assert p.case_insensitive is False

    def test_and_branch_classification(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {"$and": [{"a": 1}, {"b": {"$gte": 5}}]},
            "pipeline": None, "sort": None, "skip": None, "limit": None,
            "collation": None,
        }
        p = _build_profile(ev)
        assert p.equality_fields.get("a") == 1
        assert "b" in p.range_fields

    def test_empty_filter_produces_empty_profile(self):
        ev = {
            "op_type": "command", "collection": "Y",
            "filter": {}, "pipeline": None,
            "sort": None, "skip": None, "limit": None, "collation": None,
        }
        p = _build_profile(ev)
        assert p.equality_fields == {}
        assert p.range_fields == set()
        assert p.text_fields == set()
        assert p.text_query is None
