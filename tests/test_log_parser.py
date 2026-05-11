"""Tests for the slow-query event extraction in main.py."""

from __future__ import annotations

import json

import pytest

from main import (
    SKIP_DB_PREFIXES,
    _stringify_ts,
    extract_event,
    is_slow_query,
    iter_log_lines,
)


# ---------------------------------------------------------------------------
# is_slow_query()
# ---------------------------------------------------------------------------

class TestIsSlowQuery:
    def test_command_slow_query(self, slow_query_text_aggregate):
        assert is_slow_query(slow_query_text_aggregate)

    def test_write_slow_query(self):
        assert is_slow_query({"c": "WRITE", "msg": "Slow query"})

    def test_query_component_slow_query(self):
        assert is_slow_query({"c": "QUERY", "msg": "Slow query"})

    def test_network_event_rejected(self, non_slow_query_network_event):
        assert not is_slow_query(non_slow_query_network_event)

    def test_wrong_msg_rejected(self):
        assert not is_slow_query({"c": "COMMAND", "msg": "Connection accepted"})

    def test_non_dict_rejected(self):
        assert not is_slow_query("not a dict")  # type: ignore[arg-type]
        assert not is_slow_query(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _stringify_ts()
# ---------------------------------------------------------------------------

class TestStringifyTs:
    def test_extended_json_date(self):
        ts = {"$date": "2026-04-01T23:58:48.874+00:00"}
        assert _stringify_ts(ts) == "2026-04-01T23:58:48.874+00:00"

    def test_plain_string(self):
        assert _stringify_ts("2026-04-01") == "2026-04-01"

    def test_none_returns_empty(self):
        assert _stringify_ts(None) == ""

    def test_unknown_returns_empty(self):
        assert _stringify_ts(42) == ""


# ---------------------------------------------------------------------------
# extract_event() on each fixture shape
# ---------------------------------------------------------------------------

class TestExtractEvent:
    def test_text_aggregate(self, slow_query_text_aggregate):
        ev = extract_event(slow_query_text_aggregate)
        assert ev is not None
        assert ev["ns"] == "FalconFlexTripsSvcProd.Task"
        assert ev["collection"] == "Task"
        assert ev["op_type"] == "command"
        # pipeline preserved
        assert isinstance(ev["pipeline"], list) and len(ev["pipeline"]) == 7
        # sort lifted from $sort stage
        assert ev["sort"] == {"CreatedAtUtc": -1}
        # first $limit wins (20000, not the trailing 6)
        assert ev["limit"] == 20000
        # skip from the $skip stage
        assert ev["skip"] == 0
        # planSummary preserved
        assert "_fts" in ev["plan_summary"]
        assert ev["query_hash"] == "A1A6B6AF"
        assert ev["plan_cache_key"] == "67250F6E"
        assert ev["duration_ms"] == 211
        assert ev["docs_examined"] == 68052
        assert ev["keys_examined"] == 35060
        assert ev["app_name"] == "FalconFlex-Production"

    def test_find_collscan(self, slow_query_find_collscan):
        ev = extract_event(slow_query_find_collscan)
        assert ev is not None
        assert ev["ns"] == "FalconFlexTripsSvcProd.RelocationTask"
        assert ev["filter"] == {}
        assert ev["pipeline"] is None
        # skip + limit pulled from command body (find), not pipeline
        assert ev["skip"] == 300000
        assert ev["limit"] == 10000
        assert ev["plan_summary"] == "COLLSCAN"

    def test_find_with_regex(self, slow_query_regex_case_insens):
        ev = extract_event(slow_query_regex_case_insens)
        assert ev["filter"]["Email"]["$regex"] == ".*@example\\.com$"
        assert ev["filter"]["Email"]["$options"] == "i"

    def test_collation_extracted(self):
        entry = {
            "t": {"$date": "2026-04-02T00:00:00.000+00:00"},
            "c": "COMMAND", "msg": "Slow query",
            "attr": {
                "ns": "X.Y",
                "command": {
                    "find": "Y", "$db": "X", "filter": {},
                    "collation": {"locale": "en", "strength": 2},
                },
                "durationMillis": 50,
            },
        }
        ev = extract_event(entry)
        assert ev["collation"] == {"locale": "en", "strength": 2}

    def test_invalid_command_returns_none(self):
        entry = {"c": "COMMAND", "msg": "Slow query", "attr": {"command": "not a dict"}}
        assert extract_event(entry) is None

    def test_missing_attr_returns_none(self):
        assert extract_event({"c": "COMMAND", "msg": "Slow query"}) is None

    def test_first_limit_wins_in_pipeline(self):
        # Two $limit stages — should take the first
        entry = {
            "c": "COMMAND", "msg": "Slow query",
            "attr": {
                "ns": "X.Y",
                "command": {
                    "aggregate": "Y", "$db": "X",
                    "pipeline": [{"$limit": 1000}, {"$limit": 5}],
                },
                "durationMillis": 1,
            },
        }
        ev = extract_event(entry)
        assert ev["limit"] == 1000

    def test_ns_constructed_from_command_when_missing(self):
        entry = {
            "c": "COMMAND", "msg": "Slow query",
            "attr": {
                "command": {"find": "Users", "$db": "MyApp"},
                "durationMillis": 1,
            },
        }
        ev = extract_event(entry)
        assert ev["ns"] == "MyApp.Users"
        assert ev["collection"] == "Users"


# ---------------------------------------------------------------------------
# iter_log_lines() — including malformed lines
# ---------------------------------------------------------------------------

class TestIterLogLines:
    def test_parses_valid_jsonl(self, tmp_path):
        p = tmp_path / "x.log"
        lines = [
            '{"t":{"$date":"2026-01-01T00:00:00.000+00:00"},"c":"NETWORK","msg":"x"}',
            '{"c":"COMMAND","msg":"Slow query","attr":{"command":{"find":"Y","$db":"X"},"ns":"X.Y","durationMillis":1}}',
        ]
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        results = list(iter_log_lines(p))
        assert len(results) == 2
        assert results[0][2] is not None
        assert results[1][2] is not None

    def test_malformed_line_yields_none(self, tmp_path):
        p = tmp_path / "x.log"
        p.write_text("not json at all\n{}\n", encoding="utf-8")
        results = list(iter_log_lines(p))
        assert len(results) == 2
        assert results[0][2] is None    # malformed
        assert results[1][2] == {}      # valid JSON, empty object

    def test_skips_blank_lines(self, tmp_path):
        p = tmp_path / "x.log"
        p.write_text("\n\n{}\n\n", encoding="utf-8")
        results = list(iter_log_lines(p))
        assert len(results) == 1

    def test_gzip_support(self, tmp_path):
        import gzip
        p = tmp_path / "x.log.gz"
        with gzip.open(p, "wt", encoding="utf-8") as fh:
            fh.write('{"c":"COMMAND","msg":"Slow query"}\n')
        results = list(iter_log_lines(p))
        assert len(results) == 1
        assert results[0][2] == {"c": "COMMAND", "msg": "Slow query"}


# ---------------------------------------------------------------------------
# Namespace skip rules
# ---------------------------------------------------------------------------

class TestSkipPrefixes:
    @pytest.mark.parametrize("ns,should_skip", [
        ("admin.foo", True),
        ("local.oplog.rs", True),
        ("config.shards", True),
        ("$external.users", True),
        ("MyApp.Users", False),
        ("FalconFlexTripsSvcProd.Task", False),
    ])
    def test_skip_internal_namespaces(self, ns, should_skip):
        assert ns.startswith(SKIP_DB_PREFIXES) == should_skip
