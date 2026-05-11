"""Test fixtures shared across the suite.

Pytest auto-discovers this file and makes its fixtures available without
explicit imports. Inline fixtures (dicts, strings) live here when reused
across files; fixture files (.log, .csv) live in tests/fixtures/.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the project root importable as a normal package so `import main`
# works from anywhere in the test suite.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Synthetic log-entry fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def slow_query_text_aggregate() -> dict:
    """Mirror of the FalconFlex $text aggregate slow query."""
    return {
        "t": {"$date": "2026-04-01T23:58:52.082+00:00"},
        "s": "I",
        "c": "COMMAND",
        "id": 51803,
        "ctx": "conn815711",
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "FalconFlexTripsSvcProd.Task",
            "appName": "FalconFlex-Production",
            "command": {
                "aggregate": "Task",
                "pipeline": [
                    {"$match": {"$text": {"$search": '"(Reverse)"'}}},
                    {"$match": {"ExecutingCompanyId": "61b0d247360a67f5f35da9cb"}},
                    {"$match": {"StatusId": 1}},
                    {"$limit": 20000},
                    {"$sort": {"CreatedAtUtc": -1}},
                    {"$skip": 0},
                    {"$limit": 6},
                ],
                "$db": "FalconFlexTripsSvcProd",
            },
            "planSummary": 'IXSCAN { _fts: "text", _ftsx: 1 }',
            "keysExamined": 35060,
            "docsExamined": 68052,
            "nreturned": 6,
            "queryHash": "A1A6B6AF",
            "planCacheKey": "67250F6E",
            "durationMillis": 211,
        },
    }


@pytest.fixture
def slow_query_find_collscan() -> dict:
    """A find() with empty filter that triggers COLLSCAN."""
    return {
        "t": {"$date": "2026-04-02T00:05:55.082+00:00"},
        "s": "I",
        "c": "COMMAND",
        "id": 51803,
        "ctx": "conn817566",
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "FalconFlexTripsSvcProd.RelocationTask",
            "command": {
                "find": "RelocationTask",
                "filter": {},
                "skip": 300000,
                "limit": 10000,
                "$db": "FalconFlexTripsSvcProd",
            },
            "planSummary": "COLLSCAN",
            "durationMillis": 1010,
            "docsExamined": 194172,
            "nreturned": 0,
        },
    }


@pytest.fixture
def slow_query_regex_case_insens() -> dict:
    """A find() with a case-insensitive leading-wildcard regex."""
    return {
        "t": {"$date": "2026-04-02T01:00:00.000+00:00"},
        "s": "I",
        "c": "COMMAND",
        "id": 51803,
        "ctx": "conn1",
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "MyApp.Users",
            "command": {
                "find": "Users",
                "filter": {"Email": {"$regex": ".*@example\\.com$", "$options": "i"}},
                "$db": "MyApp",
            },
            "planSummary": "COLLSCAN",
            "durationMillis": 500,
            "docsExamined": 50000,
            "nreturned": 12,
            "queryHash": "DEADBEEF",
        },
    }


@pytest.fixture
def slow_query_or_searchbar() -> dict:
    """The classic 'search bar' pattern: $or over several string fields."""
    return {
        "t": {"$date": "2026-04-02T02:00:00.000+00:00"},
        "s": "I",
        "c": "COMMAND",
        "id": 51803,
        "ctx": "conn1",
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "MyApp.Products",
            "command": {
                "find": "Products",
                "filter": {
                    "$or": [
                        {"Name": {"$regex": "widget", "$options": "i"}},
                        {"Description": {"$regex": "widget", "$options": "i"}},
                        {"Sku": "widget"},
                    ]
                },
                "$db": "MyApp",
            },
            "planSummary": "COLLSCAN",
            "durationMillis": 300,
            "docsExamined": 80000,
            "nreturned": 3,
            "queryHash": "CAFEBABE",
        },
    }


@pytest.fixture
def slow_query_with_range() -> dict:
    """A find() with $gte/$lte range — should NOT be an Atlas Search opportunity."""
    return {
        "t": {"$date": "2026-04-02T03:00:00.000+00:00"},
        "s": "I",
        "c": "COMMAND",
        "id": 51803,
        "ctx": "conn1",
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "MyApp.Orders",
            "command": {
                "find": "Orders",
                "filter": {
                    "CreatedAtUtc": {
                        "$gte": {"$date": "2026-04-01T00:00:00.000Z"},
                        "$lte": {"$date": "2026-04-02T00:00:00.000Z"},
                    },
                    "Status": "PAID",
                },
                "$db": "MyApp",
            },
            "planSummary": "IXSCAN { CreatedAtUtc: 1 }",
            "durationMillis": 150,
            "keysExamined": 5000,
            "docsExamined": 5000,
            "nreturned": 4800,
            "queryHash": "12345678",
        },
    }


@pytest.fixture
def non_slow_query_network_event() -> dict:
    """A NETWORK 'Connection accepted' line — should be ignored."""
    return {
        "t": {"$date": "2026-04-01T23:58:48.874+00:00"},
        "s": "I",
        "c": "NETWORK",
        "id": 22943,
        "ctx": "listener",
        "msg": "Connection accepted",
        "attr": {"remote": "192.168.0.1:1234"},
    }


# ---------------------------------------------------------------------------
# CSV fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def index_csv_path(tmp_path) -> Path:
    """Synthetic CSV mirroring the FalconFlex index dump format."""
    p = tmp_path / "indexes.csv"
    p.write_text(
        "DB Name,Collection Name,Name,Type,Size (MB),Fragmented Size (MB),"
        "# Primary Ops,# Secondary Ops,Key,Options,isDuplicate\n"
        # _id index (never a drop candidate)
        'MyApp,Users,_id_,mongod,12.5,0.0,1000,500,"{ _id: 1 }",,false\n'
        # text index with weights in JSON form
        'MyApp,Users,UsersTextIdx,mongod,45.2,3.1,200,50,'
        '"{ _fts: ""text"", _ftsx: 1 }",'
        '"{""weights"":{""Email"":1,""Name"":2},""default_language"":""english""}",'
        'false\n'
        # Single-field index with ops (keep)
        'MyApp,Users,EmailIdx,mongod,8.0,0.5,15000,800,"{ Email: 1 }",,false\n'
        # Compound index with zero ops (drop candidate — unused)
        'MyApp,Users,LegacyIdx,mongod,30.0,1.0,0,0,'
        '"{ CreatedAtUtc: 1, UpdatedAtUtc: -1 }",,false\n'
        # Duplicate index (drop candidate)
        'MyApp,Users,EmailIdxDup,mongod,8.0,0.0,0,0,"{ Email: 1 }",,true\n'
        # TTL index (display_type should be "ttl")
        'MyApp,Sessions,TTL_Sessions,mongod,2.0,0.0,100,80,'
        '"{ ExpiresAt: 1 }","{""expireAfterSeconds"":3600}",false\n'
        # 2dsphere index
        'MyApp,Stores,GeoIdx,mongod,5.5,0.2,500,300,'
        '"{ Location: ""2dsphere"" }",,false\n'
        # Index in the unquoted-key mongo-doc form
        'MyApp,Orders,OrderCompoundIdx,mongod,18.0,0.5,800,400,'
        '"{ UserId: 1, CreatedAtUtc: -1 }",,false\n',
        encoding="utf-8",
    )
    return p
