"""Tests for the Atlas Search recommendation engine (recommend.py)."""

from __future__ import annotations

import pytest

from indexes import IndexCatalog, IndexEntry, load_catalog
from main import _build_profile, detect, extract_event, QueryShape
from recommend import (
    QueryProfile,
    build_index_definition,
    build_notes,
    build_search_pipeline,
    enrich_with_catalog,
    find_replaced_indexes,
    _regex_to_wildcard,
    _strip_regex_anchors,
)


# ---------------------------------------------------------------------------
# Index definition synthesizer
# ---------------------------------------------------------------------------

class TestBuildIndexDefinition:
    def test_text_field_uses_standard_analyzer(self):
        p = QueryProfile(text_fields={"Description"})
        idx = build_index_definition(p)
        f = idx["mappings"]["fields"]["Description"]
        assert f == {"type": "string", "analyzer": "lucene.standard"}

    def test_autocomplete_field_uses_edgeGram(self):
        p = QueryProfile(autocomplete_fields={"Title"})
        idx = build_index_definition(p)
        f = idx["mappings"]["fields"]["Title"]
        assert f["type"] == "autocomplete"
        assert f["tokenization"] == "edgeGram"
        assert f["minGrams"] == 2 and f["maxGrams"] == 15
        assert f["foldDiacritics"] is True

    def test_string_equality_uses_token_with_lowercase(self):
        p = QueryProfile(equality_fields={"Status": "PAID"})
        idx = build_index_definition(p)
        f = idx["mappings"]["fields"]["Status"]
        assert f == {"type": "token", "normalizer": "lowercase"}

    def test_number_equality_uses_number_type(self):
        p = QueryProfile(equality_fields={"StatusId": 1})
        idx = build_index_definition(p)
        assert idx["mappings"]["fields"]["StatusId"] == {"type": "number"}

    def test_bool_equality_uses_boolean_type(self):
        p = QueryProfile(equality_fields={"Active": True})
        idx = build_index_definition(p)
        assert idx["mappings"]["fields"]["Active"] == {"type": "boolean"}

    def test_date_dict_uses_date_type(self):
        p = QueryProfile(equality_fields={"CreatedAt": {"$date": "2026-01-01"}})
        idx = build_index_definition(p)
        assert idx["mappings"]["fields"]["CreatedAt"] == {"type": "date"}

    def test_range_field_uses_date_default(self):
        p = QueryProfile(range_fields={"CreatedAt"})
        idx = build_index_definition(p)
        assert idx["mappings"]["fields"]["CreatedAt"] == {"type": "date"}

    def test_sort_field_added_when_not_already_indexed(self):
        p = QueryProfile(sort_fields=[("CreatedAt", -1)])
        idx = build_index_definition(p)
        assert "CreatedAt" in idx["mappings"]["fields"]

    def test_sort_field_does_not_override_existing_mapping(self):
        # If a field is already mapped (e.g. as text), don't clobber
        p = QueryProfile(text_fields={"Title"}, sort_fields=[("Title", 1)])
        idx = build_index_definition(p)
        f = idx["mappings"]["fields"]["Title"]
        # Should still be the string mapping, not a date
        assert f == {"type": "string", "analyzer": "lucene.standard"}

    def test_dynamic_false(self):
        p = QueryProfile(text_fields={"X"})
        idx = build_index_definition(p)
        assert idx["mappings"]["dynamic"] is False

    def test_index_name_default(self):
        p = QueryProfile(text_fields={"X"})
        idx = build_index_definition(p)
        assert idx["name"] == "default"

    def test_index_name_override(self):
        p = QueryProfile(text_fields={"X"})
        idx = build_index_definition(p, name="my_index")
        assert idx["name"] == "my_index"


# ---------------------------------------------------------------------------
# $search pipeline rewriter
# ---------------------------------------------------------------------------

class TestBuildSearchPipeline:
    def test_text_query_emits_text_operator(self):
        p = QueryProfile(text_query="hello world", text_fields={"Description"})
        pipe = build_search_pipeline(p)
        search = pipe[0]["$search"]
        assert search["compound"]["must"][0] == {
            "text": {"query": "hello world", "path": "Description"}
        }

    def test_text_query_with_multiple_paths(self):
        p = QueryProfile(text_query="hello",
                         text_fields={"Name", "Description"})
        pipe = build_search_pipeline(p)
        clause = pipe[0]["$search"]["compound"]["must"][0]
        assert clause["text"]["query"] == "hello"
        assert sorted(clause["text"]["path"]) == ["Description", "Name"]

    def test_regex_without_anchor_uses_wildcard(self):
        p = QueryProfile(regex_patterns=[("Name", "widget")],
                         text_fields={"Name"})
        pipe = build_search_pipeline(p)
        clause = pipe[0]["$search"]["compound"]["must"][0]
        assert "wildcard" in clause
        assert clause["wildcard"]["path"] == "Name"
        assert clause["wildcard"]["allowAnalyzedField"] is True

    def test_leading_wildcard_uses_autocomplete(self):
        p = QueryProfile(regex_patterns=[("Name", ".*foo")],
                         autocomplete_fields={"Name"})
        pipe = build_search_pipeline(p)
        clause = pipe[0]["$search"]["compound"]["must"][0]
        assert "autocomplete" in clause
        assert clause["autocomplete"]["path"] == "Name"
        # `.*foo` strips to `foo`
        assert clause["autocomplete"]["query"] == "foo"

    def test_or_branches_become_should(self):
        # When there's no text_query but $or has text fields
        p = QueryProfile(or_text_fields={"Name", "Description"})
        pipe = build_search_pipeline(p)
        compound = pipe[0]["$search"]["compound"]
        assert "should" in compound
        assert compound.get("minimumShouldMatch") == 1
        paths = {clause["text"]["path"] for clause in compound["should"]}
        assert paths == {"Name", "Description"}

    def test_equality_fields_become_compound_filter(self):
        p = QueryProfile(
            text_query="x", text_fields={"Title"},
            equality_fields={"Status": "PAID", "Count": 5},
        )
        pipe = build_search_pipeline(p)
        compound = pipe[0]["$search"]["compound"]
        filters = {clause["equals"]["path"]: clause["equals"]["value"]
                   for clause in compound["filter"]}
        assert filters == {"Status": "PAID", "Count": 5}

    def test_objectid_equality_skipped(self):
        p = QueryProfile(
            text_query="x", text_fields={"T"},
            equality_fields={"UserId": {"$oid": "abc123"}, "Status": "OK"},
        )
        pipe = build_search_pipeline(p)
        compound = pipe[0]["$search"]["compound"]
        paths = {c["equals"]["path"] for c in compound.get("filter", [])}
        assert "UserId" not in paths       # skipped
        assert "Status" in paths

    def test_range_fields_become_compound_filter_range(self):
        p = QueryProfile(text_query="x", text_fields={"T"},
                         range_fields={"CreatedAt"})
        pipe = build_search_pipeline(p)
        compound = pipe[0]["$search"]["compound"]
        ranges = [c for c in compound["filter"] if "range" in c]
        assert len(ranges) == 1
        assert ranges[0]["range"]["path"] == "CreatedAt"

    def test_sort_skip_limit_appended(self):
        p = QueryProfile(text_query="x", text_fields={"T"},
                         sort_fields=[("CreatedAt", -1)], skip=10, limit=20)
        pipe = build_search_pipeline(p)
        # Stages after $search: $sort, $skip, $limit (in that order)
        assert pipe[1] == {"$sort": {"CreatedAt": -1}}
        assert pipe[2] == {"$skip": 10}
        assert pipe[3] == {"$limit": 20}

    def test_skip_zero_omitted(self):
        # falsy skip → not emitted
        p = QueryProfile(text_query="x", text_fields={"T"}, limit=5)
        pipe = build_search_pipeline(p)
        # only $search + $limit
        assert len(pipe) == 2
        assert "$skip" not in [list(s.keys())[0] for s in pipe[1:]]

    def test_empty_profile_emits_placeholder(self):
        p = QueryProfile()
        pipe = build_search_pipeline(p)
        compound = pipe[0]["$search"]["compound"]
        assert "must" in compound
        assert compound["must"][0]["text"]["query"] == "<USER_SEARCH_TERM>"


# ---------------------------------------------------------------------------
# Notes generator
# ---------------------------------------------------------------------------

class TestBuildNotes:
    def test_always_includes_review_note(self):
        p = QueryProfile()
        notes = build_notes(p)
        assert any("Review analyzer" in n for n in notes)

    def test_phrase_note_when_text_query(self):
        p = QueryProfile(text_query="x", text_fields={"T"})
        notes = build_notes(p)
        assert any("phrase" in n.lower() for n in notes)

    def test_autocomplete_note_when_present(self):
        p = QueryProfile(autocomplete_fields={"X"})
        notes = build_notes(p)
        assert any("autocomplete" in n.lower() for n in notes)

    def test_case_insensitive_note(self):
        p = QueryProfile(case_insensitive=True)
        notes = build_notes(p)
        assert any("case" in n.lower() for n in notes)

    def test_sort_note(self):
        p = QueryProfile(sort_fields=[("X", 1)])
        notes = build_notes(p)
        assert any("Sort" in n or "score" in n.lower() for n in notes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestRegexHelpers:
    @pytest.mark.parametrize("pat,expected", [
        ("^foo", "foo"),
        ("foo$", "foo"),
        ("^foo$", "foo"),
        (".*foo.*", "foo"),
        ("^.*foo.*$", "foo"),
        ("foo", "foo"),
    ])
    def test_strip_regex_anchors(self, pat, expected):
        assert _strip_regex_anchors(pat) == expected

    def test_strip_regex_handles_non_string(self):
        assert _strip_regex_anchors(None) == ""  # type: ignore[arg-type]

    @pytest.mark.parametrize("pat,expected", [
        ("^foo", "foo"),
        ("foo$", "foo"),
        (".*foo.*", "*foo*"),
        ("f.o", "f?o"),
    ])
    def test_regex_to_wildcard(self, pat, expected):
        assert _regex_to_wildcard(pat) == expected


# ---------------------------------------------------------------------------
# Catalog enrichment
# ---------------------------------------------------------------------------

class TestEnrichWithCatalog:
    def test_resolves_text_indexed_field_placeholder(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        p = QueryProfile(text_query="hello", text_fields={"<TEXT_INDEXED_FIELD>"})
        enrich_with_catalog(p, "MyApp.Users", cat)
        # Placeholder gone; real weights present
        assert "<TEXT_INDEXED_FIELD>" not in p.text_fields
        assert {"Email", "Name"} <= p.text_fields

    def test_no_catalog_is_safe(self):
        p = QueryProfile(text_fields={"<TEXT_INDEXED_FIELD>"})
        enrich_with_catalog(p, "X.Y", None)
        # Unchanged
        assert "<TEXT_INDEXED_FIELD>" in p.text_fields

    def test_no_text_index_leaves_placeholder(self, index_csv_path):
        # MyApp.Sessions has no text index; placeholder should remain
        cat = load_catalog(index_csv_path)
        p = QueryProfile(text_fields={"<TEXT_INDEXED_FIELD>"})
        enrich_with_catalog(p, "MyApp.Sessions", cat)
        assert "<TEXT_INDEXED_FIELD>" in p.text_fields


# ---------------------------------------------------------------------------
# find_replaced_indexes
# ---------------------------------------------------------------------------

class TestFindReplacedIndexes:
    def test_replaces_covered_indexes(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # Atlas Search index that covers {Email, Name}
        p = QueryProfile(text_fields={"Email", "Name"})
        replaced = find_replaced_indexes(p, "MyApp.Users", cat)
        names = {e.name for e in replaced}
        # EmailIdx (Email) is a subset of {Email, Name}
        assert "EmailIdx" in names
        assert "EmailIdxDup" in names

    def test_excludes_non_subset_indexes(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # Atlas Search covering only Email — should NOT include LegacyIdx
        p = QueryProfile(text_fields={"Email"})
        replaced = find_replaced_indexes(p, "MyApp.Users", cat)
        names = {e.name for e in replaced}
        assert "LegacyIdx" not in names

    def test_excludes_id_index(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # Even if a search index covers {_id}, never claim to replace _id_
        p = QueryProfile(equality_fields={"_id": 1})
        replaced = find_replaced_indexes(p, "MyApp.Users", cat)
        names = {e.name for e in replaced}
        assert "_id_" not in names

    def test_skips_placeholder_fields(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # If profile only has placeholders, no real indexes can match
        p = QueryProfile(text_fields={"<TEXT_INDEXED_FIELD>"})
        assert find_replaced_indexes(p, "MyApp.Users", cat) == []

    def test_no_catalog_returns_empty(self):
        p = QueryProfile(text_fields={"X"})
        assert find_replaced_indexes(p, "X.Y", None) == []


# ---------------------------------------------------------------------------
# End-to-end: realistic FalconFlex-like query → recommendation
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_falconflex_task_aggregate(self, slow_query_text_aggregate, index_csv_path):
        """The whole pipeline: log entry → profile → recommendation."""
        ev = extract_event(slow_query_text_aggregate)
        shape = QueryShape(
            query_hash=ev["query_hash"],
            plan_cache_key=ev["plan_cache_key"],
            namespace=ev["ns"],
            op_type=ev["op_type"],
        )
        detect(ev, shape)
        # Catalog has no MyApp.Task, so placeholder stays — that's fine; this
        # test focuses on the assembled pipeline shape.
        pipe = build_search_pipeline(shape.profile)

        # 1. Starts with $search
        assert "$search" in pipe[0]
        # 2. Contains text query
        must = pipe[0]["$search"]["compound"]["must"]
        assert any(clause.get("text", {}).get("query") == '"(Reverse)"'
                   for clause in must)
        # 3. Both equality filters preserved
        filters = pipe[0]["$search"]["compound"]["filter"]
        paths = {c["equals"]["path"] for c in filters}
        assert paths == {"ExecutingCompanyId", "StatusId"}
        # 4. Sort + limit appended
        assert {"$sort": {"CreatedAtUtc": -1}} in pipe
        assert {"$limit": 20000} in pipe
