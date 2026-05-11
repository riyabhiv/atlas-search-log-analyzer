"""Tests for indexes.py — CSV loader, key parser, drop-candidate logic."""

from __future__ import annotations

import pytest

from indexes import (
    IndexCatalog,
    IndexEntry,
    _parse_key_doc,
    _parse_weights,
    _to_bool,
    _to_float,
    _to_int,
    load_catalog,
)


# ---------------------------------------------------------------------------
# Key-doc parser
# ---------------------------------------------------------------------------

class TestParseKeyDoc:
    def test_simple_unquoted_field(self):
        assert _parse_key_doc("{ field: 1 }") == {"field": 1}

    def test_simple_quoted_field(self):
        assert _parse_key_doc('{"field": 1}') == {"field": 1}

    def test_compound_mixed_direction(self):
        assert _parse_key_doc("{ a: 1, b: -1 }") == {"a": 1, "b": -1}

    def test_text_index_with_fts_ftsx(self):
        # MongoDB text indexes always have these synthetic companion keys
        out = _parse_key_doc('{ _fts: "text", _ftsx: 1 }')
        assert out == {"_fts": "text", "_ftsx": 1}

    def test_dotted_field_name(self):
        out = _parse_key_doc('{ "DeliveryLocation.Name": 1 }')
        assert out == {"DeliveryLocation.Name": 1}

    def test_2dsphere_value(self):
        out = _parse_key_doc('{ Location: "2dsphere" }')
        assert out == {"Location": "2dsphere"}

    def test_hashed_value(self):
        out = _parse_key_doc("{ UserId: hashed }")
        assert out == {"UserId": "hashed"}

    def test_no_braces(self):
        # Tolerate a stripped form
        assert _parse_key_doc("field: 1, other: -1") == {"field": 1, "other": -1}

    def test_empty(self):
        assert _parse_key_doc("") == {}
        assert _parse_key_doc("{}") == {}

    def test_malformed_returns_partial_or_empty(self):
        # The parser is forgiving and skips garbage; should never raise
        out = _parse_key_doc("{ garbage broken }")
        assert isinstance(out, dict)

    def test_compound_with_fts(self):
        # Real-world example: partial text + standard field
        out = _parse_key_doc('{ _fts: "text", _ftsx: 1, CompanyId: 1 }')
        assert out == {"_fts": "text", "_ftsx": 1, "CompanyId": 1}


class TestParseWeights:
    def test_json_form(self):
        opts = '{"weights":{"Email":1,"Name":2},"default_language":"english"}'
        assert _parse_weights(opts) == ["Email", "Name"]

    def test_mongo_doc_form(self):
        opts = "{ weights: { Email: 1, Name: 2 }, default_language: english }"
        assert _parse_weights(opts) == ["Email", "Name"]

    def test_dotted_field_names(self):
        opts = '{"weights":{"DeliveryLocation.Name":1,"ShortId":1}}'
        assert _parse_weights(opts) == ["DeliveryLocation.Name", "ShortId"]

    def test_no_weights(self):
        assert _parse_weights('{"sparse":false}') == []

    def test_empty_string(self):
        assert _parse_weights("") == []

    def test_preserves_first_occurrence_order(self):
        opts = '{"weights":{"a":1,"b":1,"c":1,"a":2}}'  # duplicate `a`
        result = _parse_weights(opts)
        assert result[0] == "a"
        assert "b" in result and "c" in result


# ---------------------------------------------------------------------------
# Value coercion
# ---------------------------------------------------------------------------

class TestValueCoercion:
    @pytest.mark.parametrize("raw,expected", [
        ("1.5", 1.5),
        ("1,234.5", 1234.5),
        ("", 0.0),
        ("not-a-number", 0.0),
        ("0", 0.0),
    ])
    def test_to_float(self, raw, expected):
        assert _to_float(raw) == expected

    @pytest.mark.parametrize("raw,expected", [
        ("42", 42),
        ("1,000,000", 1000000),
        ("3.7", 3),
        ("", 0),
        ("bogus", 0),
    ])
    def test_to_int(self, raw, expected):
        assert _to_int(raw) == expected

    @pytest.mark.parametrize("raw,expected", [
        ("true", True), ("True", True), ("TRUE", True),
        ("1", True), ("yes", True), ("Y", True),
        ("false", False), ("False", False), ("0", False),
        ("no", False), ("", False), ("garbage", False),
    ])
    def test_to_bool(self, raw, expected):
        assert _to_bool(raw) is expected


# ---------------------------------------------------------------------------
# IndexEntry properties
# ---------------------------------------------------------------------------

class TestIndexEntry:
    def test_namespace(self):
        e = IndexEntry(db="MyApp", collection="Users", name="X", type="t")
        assert e.namespace == "MyApp.Users"

    def test_total_ops(self):
        e = IndexEntry(db="d", collection="c", name="n", type="t",
                       primary_ops=10, secondary_ops=20)
        assert e.total_ops == 30

    def test_is_text_index_by_type(self):
        e = IndexEntry(db="d", collection="c", name="n", type="text")
        assert e.is_text_index

    def test_is_text_index_by_key(self):
        e = IndexEntry(db="d", collection="c", name="n", type="mongod",
                       key={"_fts": "text", "_ftsx": 1})
        assert e.is_text_index

    def test_key_fields_strips_fts_companions(self):
        e = IndexEntry(db="d", collection="c", name="n", type="mongod",
                       key={"_fts": "text", "_ftsx": 1, "CompanyId": 1})
        assert e.key_fields == ["CompanyId"]

    def test_is_unused_true_when_zero_ops(self):
        e = IndexEntry(db="d", collection="c", name="X", type="t",
                       primary_ops=0, secondary_ops=0)
        assert e.is_unused

    def test_is_unused_false_for_id_index(self):
        # _id_ is special — never recommend dropping
        e = IndexEntry(db="d", collection="c", name="_id_", type="t",
                       primary_ops=0, secondary_ops=0)
        assert not e.is_unused

    def test_drop_candidate_duplicate(self):
        e = IndexEntry(db="d", collection="c", name="X", type="t",
                       primary_ops=10, is_duplicate=True)
        assert e.drop_candidate is not None
        assert "duplicate" in e.drop_candidate.lower()

    def test_drop_candidate_unused(self):
        e = IndexEntry(db="d", collection="c", name="X", type="t",
                       primary_ops=0, secondary_ops=0, size_mb=42.0)
        assert e.drop_candidate is not None
        assert "unused" in e.drop_candidate.lower()

    def test_drop_candidate_none_when_active(self):
        e = IndexEntry(db="d", collection="c", name="X", type="t",
                       primary_ops=5, secondary_ops=2)
        assert e.drop_candidate is None

    # display_type
    @pytest.mark.parametrize("key,opts,expected", [
        ({"_fts": "text", "_ftsx": 1}, "", "text"),
        ({"UserId": "hashed"}, "", "hashed"),
        ({"Location": "2dsphere"}, "", "2dsphere"),
        ({"X": 1}, '{"expireAfterSeconds":3600}', "ttl"),
        ({"X": 1, "Y": -1}, "", "compound"),
        ({"X": 1}, "", "single"),
        ({"X": 1}, '{"partialFilterExpression":{"x":1}}', "partial"),
    ])
    def test_display_type(self, key, opts, expected):
        e = IndexEntry(db="d", collection="c", name="n", type="mongod",
                       key=key, options_raw=opts)
        assert e.display_type == expected


# ---------------------------------------------------------------------------
# Catalog loader end-to-end
# ---------------------------------------------------------------------------

class TestLoadCatalog:
    def test_loads_all_rows(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        assert cat.parse_errors == 0
        assert len(cat.entries) == 8

    def test_namespace_index(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        users = cat.for_namespace("MyApp.Users")
        assert len(users) == 5  # _id_, UsersTextIdx, EmailIdx, LegacyIdx, EmailIdxDup
        names = {e.name for e in users}
        assert names == {"_id_", "UsersTextIdx", "EmailIdx", "LegacyIdx", "EmailIdxDup"}

    def test_text_index_fields_resolved_from_weights(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        fields = cat.text_index_fields("MyApp.Users")
        # Should come from the JSON-form weights block in Options
        assert set(fields) == {"Email", "Name"}

    def test_text_index_fields_empty_for_no_text_index(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        assert cat.text_index_fields("MyApp.Sessions") == []

    def test_covering_indexes_returns_matching(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # An Atlas Search index that covers {Email}; matches EmailIdx + EmailIdxDup
        covering = cat.covering_indexes("MyApp.Users", {"Email", "Name"})
        names = {e.name for e in covering}
        assert "EmailIdx" in names and "EmailIdxDup" in names

    def test_covering_excludes_non_subsets(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # LegacyIdx is on {CreatedAtUtc, UpdatedAtUtc} — not covered by {Email}
        covering = cat.covering_indexes("MyApp.Users", {"Email"})
        names = {e.name for e in covering}
        assert "LegacyIdx" not in names

    def test_drop_candidates_finds_duplicate_and_unused(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        drops = cat.drop_candidates()
        names = {e.name for e in drops}
        # EmailIdxDup is duplicate; LegacyIdx is zero-op
        assert "EmailIdxDup" in names
        assert "LegacyIdx" in names
        # _id_ should never be a drop candidate even with zero ops
        assert "_id_" not in names
        # EmailIdx has ops -> not a candidate
        assert "EmailIdx" not in names

    def test_drop_size_calculation(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # LegacyIdx (30 MB) + EmailIdxDup (8 MB) = 38 MB
        assert cat.total_drop_size_mb() == pytest.approx(38.0)

    def test_total_size_includes_all(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        # 12.5 + 45.2 + 8.0 + 30.0 + 8.0 + 2.0 + 5.5 + 18.0 = 129.2
        assert cat.total_size_mb() == pytest.approx(129.2)

    def test_display_types_derived_correctly(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        by_name = {e.name: e for e in cat.entries}
        assert by_name["UsersTextIdx"].display_type == "text"
        assert by_name["TTL_Sessions"].display_type == "ttl"
        assert by_name["GeoIdx"].display_type == "2dsphere"
        assert by_name["LegacyIdx"].display_type == "compound"
        assert by_name["EmailIdx"].display_type == "single"
        assert by_name["_id_"].display_type == "single"

    def test_header_alias_mapping_case_insensitive(self, tmp_path):
        # Same data as the fixture but using lower-case headers
        p = tmp_path / "indexes.csv"
        p.write_text(
            "db name,collection name,name,type,size (mb),fragmented size (mb),"
            "# primary ops,# secondary ops,key,options,isduplicate\n"
            'MyApp,Users,EmailIdx,mongod,8.0,0.5,15000,800,"{ Email: 1 }",,false\n',
            encoding="utf-8",
        )
        cat = load_catalog(p)
        assert len(cat.entries) == 1
        assert cat.entries[0].name == "EmailIdx"
        assert cat.entries[0].size_mb == 8.0

    def test_isduplicate_parsed_as_bool(self, index_csv_path):
        cat = load_catalog(index_csv_path)
        by_name = {e.name: e for e in cat.entries}
        assert by_name["EmailIdxDup"].is_duplicate is True
        assert by_name["EmailIdx"].is_duplicate is False

    def test_empty_csv_returns_empty_catalog(self, tmp_path):
        p = tmp_path / "empty.csv"
        p.write_text("", encoding="utf-8")
        cat = load_catalog(p)
        assert cat.entries == []
