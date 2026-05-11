"""
MongoDB Atlas Search Opportunity Analyzer
==========================================

Parses MongoDB structured JSON logs (4.4+) — including very large files such as
the FalconFlexPrimary.log capture — and identifies query patterns that are
strong candidates for migration to MongoDB Atlas Search.

Design borrows the streaming/aggregation approach from mhelmstetter/mongo-log-parser:
  * Stream the file line by line — never load the whole thing.
  * Only inspect "Slow query" events (mongod component=COMMAND/WRITE/QUERY).
  * Aggregate by `queryHash` + `planCacheKey` so 150k slow queries collapse
    into a few hundred distinct query *shapes*.
  * Keep one sample log message per query hash for accordion drill-down.
  * Auto-skip internal namespaces (admin/local/config).
  * Render an interactive HTML report with sticky nav, sortable & filterable
    tables, and an Atlas Search opportunity callout per query shape.

Atlas Search opportunities flagged:
  1. Legacy $text search        → Atlas Search 'text' / 'phrase' operator
  2. IXSCAN on _fts text index  → same as above (catches it from planSummary)
  3. $regex (leading-wildcard / case-insensitive)
                                → Atlas Search 'autocomplete' / 'wildcard'
  4. Multi-field $or over text  → Atlas Search compound.should ("search bar")
  5. Collation strength <=2     → Atlas Search analyzers (lowercase/diacritic)
  6. COLLSCAN touching strings  → Atlas Search index removes the scan
  7. High keysExamined / nReturned ratio on string filters
                                → text relevance scoring would be more selective

Usage:
    python main.py FalconFlexPrimary.log
    python main.py FalconFlexPrimary.log --sample 50000 --out report.html
    python main.py FalconFlexPrimary.log --min-duration 100 --redact
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Iterable

from recommend import (
    QueryProfile,
    build_index_definition,
    build_search_pipeline,
    build_notes,
    to_pretty_json,
    enrich_with_catalog,
    find_replaced_indexes,
)
from indexes import IndexCatalog, IndexEntry, load_catalog


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QUERY_COMPONENTS = {"COMMAND", "WRITE", "QUERY"}
SKIP_DB_PREFIXES = ("admin.", "local.", "config.", "$external.")

OP_KEYS = ("find", "aggregate", "update", "delete", "count", "distinct",
           "findAndModify", "findandmodify", "getMore", "insert")


# ---------------------------------------------------------------------------
# Aggregation model — one bucket per (queryHash, namespace)
# ---------------------------------------------------------------------------

@dataclass
class QueryShape:
    """Aggregated metrics + Atlas Search verdict for one distinct query shape."""
    query_hash: str
    plan_cache_key: str
    namespace: str
    op_type: str = ""               # find / aggregate / update / ...
    app_names: set[str] = field(default_factory=set)

    count: int = 0
    total_duration_ms: int = 0
    max_duration_ms: int = 0
    total_docs_examined: int = 0
    total_docs_returned: int = 0
    total_keys_examined: int = 0
    plan_summaries: Counter = field(default_factory=Counter)
    error_codes: Counter = field(default_factory=Counter)

    # Atlas Search detection state
    categories: set[str] = field(default_factory=set)
    severity: str = "low"
    reasons: list[str] = field(default_factory=list)
    or_fields: set[str] = field(default_factory=set)

    sample_filter: str = ""         # truncated JSON of filter
    sample_log_line: str = ""       # one raw log line (pretty-printed JSON)
    sample_timestamp: str = ""

    # Structured profile used by the Atlas Search recommendation engine
    profile: QueryProfile | None = None

    def docs_per_returned(self) -> float:
        if self.total_docs_returned <= 0:
            return float(self.total_docs_examined)
        return self.total_docs_examined / self.total_docs_returned

    def avg_duration_ms(self) -> float:
        return (self.total_duration_ms / self.count) if self.count else 0.0


@dataclass
class AnalysisResult:
    shapes: dict[tuple, QueryShape] = field(default_factory=dict)
    total_lines: int = 0
    parsed_lines: int = 0
    slow_query_lines: int = 0
    inspected_events: int = 0
    parse_errors: int = 0
    skipped_namespace: int = 0
    namespaces: Counter = field(default_factory=Counter)
    op_counts: Counter = field(default_factory=Counter)
    error_codes_global: Counter = field(default_factory=Counter)
    plan_summaries_global: Counter = field(default_factory=Counter)
    first_ts: str = ""
    last_ts: str = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def open_log(path: Path):
    """Open .log or .gz transparently."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def iter_log_lines(path: Path) -> Iterable[tuple[int, str, dict[str, Any] | None]]:
    """Yield (line_no, raw_line, parsed_or_None) for every non-blank line."""
    with open_log(path) as fh:
        for i, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                yield i, line, json.loads(line)
            except json.JSONDecodeError:
                yield i, line, None


def is_slow_query(entry: dict[str, Any]) -> bool:
    return (
        isinstance(entry, dict)
        and entry.get("c") in QUERY_COMPONENTS
        and entry.get("msg") == "Slow query"
    )


def extract_event(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a 'Slow query' log entry into a dict the detectors consume."""
    attr = entry.get("attr") or {}
    if not isinstance(attr, dict):
        return None

    command = attr.get("command")
    if not isinstance(command, dict):
        return None

    ns = (attr.get("ns") or "").strip()
    if not ns:
        db = command.get("$db", "")
        for k in OP_KEYS:
            if k in command and isinstance(command[k], str):
                ns = f"{db}.{command[k]}"
                break

    # Op type
    op_type = attr.get("type", "")
    if not op_type:
        for k in OP_KEYS:
            if k in command:
                op_type = k
                break

    # Find the filter — across find / aggregate / update / delete shapes.
    filt = command.get("filter") or command.get("q")
    pipeline = command.get("pipeline") if isinstance(command.get("pipeline"), list) else None

    # Extract sort / skip / limit from either the command directly (find) or
    # from any matching pipeline stages (aggregate).
    sort_doc = command.get("sort") if isinstance(command.get("sort"), dict) else None
    limit_v = command.get("limit") if isinstance(command.get("limit"), int) else None
    skip_v = command.get("skip") if isinstance(command.get("skip"), int) else None
    if pipeline:
        for stage in pipeline:
            if not isinstance(stage, dict):
                continue
            if "$sort" in stage and isinstance(stage["$sort"], dict) and sort_doc is None:
                sort_doc = stage["$sort"]
            if "$limit" in stage and isinstance(stage["$limit"], int) and limit_v is None:
                limit_v = stage["$limit"]
            if "$skip" in stage and isinstance(stage["$skip"], int) and skip_v is None:
                skip_v = stage["$skip"]

    # Collection name (without database prefix)
    collection = ns.split(".", 1)[1] if "." in ns else ns

    return {
        "ts": _stringify_ts(entry.get("t")),
        "ns": ns,
        "collection": collection,
        "op_type": op_type,
        "app_name": attr.get("appName", "") or "",
        "filter": filt if isinstance(filt, dict) else {},
        "pipeline": pipeline,
        "sort": sort_doc,
        "limit": limit_v,
        "skip": skip_v,
        "collation": command.get("collation") if isinstance(command.get("collation"), dict) else None,
        "duration_ms": int(attr.get("durationMillis", 0) or 0),
        "docs_examined": int(attr.get("docsExamined", 0) or 0),
        "docs_returned": int(attr.get("nreturned", attr.get("nReturned", 0)) or 0),
        "keys_examined": int(attr.get("keysExamined", 0) or 0),
        "plan_summary": str(attr.get("planSummary", "") or ""),
        "query_hash": str(attr.get("queryHash", "") or ""),
        "plan_cache_key": str(attr.get("planCacheKey", "") or ""),
        "err_name": str(attr.get("errName", "") or ""),
        "err_code": attr.get("errCode"),
    }


def _stringify_ts(t: Any) -> str:
    if isinstance(t, dict) and "$date" in t:
        return str(t["$date"])
    if isinstance(t, str):
        return t
    return ""


# ---------------------------------------------------------------------------
# Atlas Search detectors
# ---------------------------------------------------------------------------

CATEGORY_LABEL = {
    "text":            "Legacy $text search",
    "fts_index":       "Legacy text index (IXSCAN _fts)",
    "regex":           "$regex query",
    "leading_wildcard":"Leading-wildcard / case-insensitive regex",
    "or_multi_field":  "Multi-field $or (search-bar pattern)",
    "case_insensitive":"Case-insensitive collation",
    "collscan_string": "COLLSCAN on string filter",
    "low_selectivity": "High keysExamined : nReturned on string filter",
}

ATLAS_SUGGESTION = {
    "text": "Replace $text with Atlas Search `$search` using the `text` or `phrase` operator. "
            "You'll get language-aware analyzers, fuzzy matching, highlighting and faceting.",
    "fts_index": "An IXSCAN on `{ _fts: \"text\", _ftsx: 1 }` is a legacy MongoDB text index. "
                 "Drop it and create an Atlas Search index instead — better relevance, "
                 "no rebuild on schema change, fuzzy/autocomplete out of the box.",
    "regex": "Replace $regex with Atlas Search `text` or `autocomplete` operator. "
             "Indexed token search avoids the regex scan entirely.",
    "leading_wildcard": "Leading-wildcard regex (`/.*foo/` or `/foo/i`) cannot use a normal index. "
                        "Use Atlas Search `autocomplete` (edgeGram analyzer) or `wildcard` operator.",
    "or_multi_field": "An $or across multiple string fields is the canonical 'search bar' pattern. "
                      "Atlas Search `compound.should` indexes all fields once and ranks by relevance — "
                      "replaces N single-field regex/text indexes with one search index.",
    "case_insensitive": "Collation strength <=2 forces a collation-aware index or a COLLSCAN. "
                        "An Atlas Search `lowercase`/`diacriticFolding` token filter is faster and more flexible.",
    "collscan_string": "COLLSCAN on a filter that touches string fields is the #1 Atlas Search win. "
                       "An Atlas Search index turns this into a sub-millisecond token lookup.",
    "low_selectivity": "MongoDB scanned many keys to return very few docs — a relevance-ranked Atlas Search "
                       "query would be far more selective and let you `$limit` after scoring.",
}

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _walk(node: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(node, dict):
        for k, v in node.items():
            new_path = f"{path}.{k}" if path else k
            yield new_path, v
            yield from _walk(v, new_path)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


def _all_match_filters(event: dict[str, Any]) -> list[dict]:
    """Return every $match doc plus the top-level filter (if any) for full inspection."""
    out: list[dict] = []
    if event.get("filter"):
        out.append(event["filter"])
    pipeline = event.get("pipeline") or []
    for stage in pipeline:
        if isinstance(stage, dict):
            m = stage.get("$match")
            if isinstance(m, dict):
                out.append(m)
    return out


def _looks_text_like(cond: Any) -> bool:
    if isinstance(cond, str):
        return True
    if isinstance(cond, dict):
        if "$regex" in cond or "$text" in cond:
            return True
        if "$eq" in cond and isinstance(cond["$eq"], str):
            return True
    return False


def _filter_touches_strings(filt: Any) -> bool:
    for _, v in _walk(filt):
        if isinstance(v, str) and not v.startswith("$"):
            return True
        if isinstance(v, dict) and ("$regex" in v or "$text" in v):
            return True
    return False


def _is_scalar(v: Any) -> bool:
    return isinstance(v, (str, int, float, bool)) or v is None


# Operators we recognize on a per-field condition document
_RANGE_OPS = {"$gt", "$gte", "$lt", "$lte"}
_EQ_OPS = {"$eq"}


def _build_profile(event: dict[str, Any]) -> QueryProfile:
    """Construct a structured profile of the query's roles per field.

    This is the data the recommendation engine uses to synthesize an Atlas
    Search index and a $search pipeline.
    """
    profile = QueryProfile(
        op_type=event.get("op_type", ""),
        collection=event.get("collection", ""),
    )

    # Sort / skip / limit
    sort_doc = event.get("sort") or {}
    if isinstance(sort_doc, dict):
        for f, d in sort_doc.items():
            try:
                profile.sort_fields.append((f, int(d) if d in (-1, 1) else 1))
            except (TypeError, ValueError):
                profile.sort_fields.append((f, 1))
    if isinstance(event.get("limit"), int):
        profile.limit = event["limit"]
    if isinstance(event.get("skip"), int):
        profile.skip = event["skip"]

    # Collation
    collation = event.get("collation") or {}
    if isinstance(collation, dict) and collation.get("strength") in (1, 2):
        profile.case_insensitive = True

    filters = _all_match_filters(event)

    # Walk every filter doc at the top level (one level deep on field names)
    for filt in filters:
        if not isinstance(filt, dict):
            continue
        for fname, cond in filt.items():
            # Top-level operators ($or, $and, $text, $expr) handled separately
            if fname.startswith("$"):
                if fname == "$text" and isinstance(cond, dict):
                    term = cond.get("$search")
                    if isinstance(term, str):
                        profile.text_query = term
                elif fname == "$or" and isinstance(cond, list):
                    for branch in cond:
                        if not isinstance(branch, dict):
                            continue
                        for bname, bcond in branch.items():
                            if bname.startswith("$"):
                                continue
                            if _looks_text_like(bcond):
                                profile.or_text_fields.add(bname)
                            # Also classify ranges within $or branches
                            _classify_field_cond(profile, bname, bcond)
                elif fname == "$and" and isinstance(cond, list):
                    for branch in cond:
                        if isinstance(branch, dict):
                            for bname, bcond in branch.items():
                                if not bname.startswith("$"):
                                    _classify_field_cond(profile, bname, bcond)
                continue

            # Regular field: classify by its condition
            _classify_field_cond(profile, fname, cond)

    return profile


def _classify_field_cond(profile: QueryProfile, fname: str, cond: Any) -> None:
    """Bucket `{fname: cond}` into one of: text/equality/range/regex/autocomplete."""
    if _is_scalar(cond):
        # `{field: "value"}` or `{field: 5}` — pure equality
        if isinstance(cond, str) and cond:
            # String equality — searchable but also filterable. Treat as equality
            # (compound.filter.equals) by default; the heuristics elsewhere may
            # also flag it as text.
            profile.equality_fields[fname] = cond
        else:
            profile.equality_fields[fname] = cond
        return

    if isinstance(cond, dict):
        # $regex
        if "$regex" in cond:
            pat = cond["$regex"]
            if isinstance(pat, str):
                profile.regex_patterns.append((fname, pat))
                head = pat[:4]
                if head.startswith(".*") or head.startswith("^.*") or ".*" in head:
                    profile.autocomplete_fields.add(fname)
                else:
                    profile.text_fields.add(fname)
            return

        # $in with strings → treat as equality (will become $in-style filter)
        if "$in" in cond and isinstance(cond["$in"], list) and cond["$in"]:
            profile.equality_fields[fname] = cond["$in"][0]  # sample
            return

        # Range operators
        if any(op in cond for op in _RANGE_OPS):
            profile.range_fields.add(fname)
            return

        # $eq
        if "$eq" in cond and _is_scalar(cond["$eq"]):
            profile.equality_fields[fname] = cond["$eq"]
            return

        # $ne / $exists / $type — keep as residual (no Atlas Search mapping)
        # We deliberately don't add these to the profile.


def detect(event: dict[str, Any], shape: QueryShape) -> None:
    """Run all detectors; mutate shape in-place to record categories/severity.

    Also builds a structured QueryProfile that the recommendation engine
    uses to synthesize an Atlas Search index + $search pipeline.
    """
    filters = _all_match_filters(event)
    plan = (event.get("plan_summary") or "").upper()

    # Build the structured profile first
    shape.profile = _build_profile(event)

    # Now run yes/no detectors on top of it
    has_regex = bool(shape.profile.regex_patterns)
    regex_lead_wild = bool(shape.profile.autocomplete_fields)
    regex_case_insens = False
    has_text = shape.profile.text_query is not None
    in_or = bool(shape.profile.or_text_fields)
    or_text_fields = shape.profile.or_text_fields

    # Rescan once for $options i (not stored on profile)
    for filt in filters:
        for path, value in _walk(filt):
            last = path.rsplit(".", 1)[-1]
            if last == "$options" and isinstance(value, str) and "i" in value:
                regex_case_insens = True
                break

    # Promote text-search intent: if $text was present, the searchable fields
    # are wherever the legacy text index lives — we don't know which from the
    # log alone, so we emit a placeholder field name that the user replaces.
    if has_text and not shape.profile.text_fields:
        shape.profile.text_fields.add("<TEXT_INDEXED_FIELD>")

    # Plan summary signal: legacy text index
    fts_index = "IXSCAN" in plan and "_FTS" in plan

    # Collation
    collation = event.get("collation") or {}
    case_insens_collation = isinstance(collation, dict) and collation.get("strength") in (1, 2)

    if has_text:
        shape.categories.add("text")
        shape.reasons.append("Uses legacy `$text` operator.")
    if fts_index and "text" not in shape.categories:
        shape.categories.add("fts_index")
        shape.reasons.append(f"planSummary `{event.get('plan_summary')}` indicates a legacy text index.")
        if not shape.profile.text_fields:
            shape.profile.text_fields.add("<TEXT_INDEXED_FIELD>")

    if has_regex:
        if regex_lead_wild or regex_case_insens:
            shape.categories.add("leading_wildcard")
            bits = []
            if regex_lead_wild:
                bits.append("leading wildcard prevents index use")
            if regex_case_insens:
                bits.append("case-insensitive flag forces collation/scan")
                # Promote regex'd fields to autocomplete role for /i case
                for f, _pat in shape.profile.regex_patterns:
                    shape.profile.autocomplete_fields.add(f)
                    shape.profile.text_fields.discard(f)
            shape.reasons.append("$regex with " + " + ".join(bits) + ".")
        else:
            shape.categories.add("regex")
            shape.reasons.append("Filter contains `$regex`.")

    if in_or and len(or_text_fields) >= 2:
        shape.categories.add("or_multi_field")
        shape.or_fields.update(or_text_fields)
        shape.reasons.append(
            f"$or across {len(or_text_fields)} fields ({', '.join(sorted(or_text_fields))}) "
            "— classic search-bar pattern."
        )

    if case_insens_collation:
        shape.categories.add("case_insensitive")
        shape.reasons.append(f"Collation strength={collation.get('strength')} (case/diacritic-insensitive).")

    if "COLLSCAN" in plan and any(_filter_touches_strings(f) for f in filters):
        shape.categories.add("collscan_string")
        shape.reasons.append("COLLSCAN on a filter that touches string fields.")

    # Low-selectivity heuristic — only if we have meaningful counts
    if (event.get("keys_examined", 0) >= 1000
            and event.get("docs_returned", 0) > 0
            and event["keys_examined"] / max(event["docs_returned"], 1) >= 100
            and any(_filter_touches_strings(f) for f in filters)):
        shape.categories.add("low_selectivity")

    # Compute severity (max over categories)
    sev_for_cat = {
        "text":             "high",
        "fts_index":        "high",
        "leading_wildcard": "high",
        "or_multi_field":   "high",
        "collscan_string":  "high",
        "regex":            "medium",
        "case_insensitive": "medium",
        "low_selectivity":  "medium",
    }
    if shape.categories:
        shape.severity = min(
            (sev_for_cat.get(c, "low") for c in shape.categories),
            key=lambda s: SEVERITY_RANK[s],
        )


# ---------------------------------------------------------------------------
# Redaction (mongo-log-parser style)
# ---------------------------------------------------------------------------

def redact_value(v: Any) -> Any:
    if isinstance(v, str):
        # keep ObjectId-looking refs structurally similar but obfuscated
        return "xxx"
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return int("9" * len(str(abs(v)))) if v else 0
    if isinstance(v, float):
        return 9.9
    if isinstance(v, list):
        return [redact_value(x) for x in v]
    if isinstance(v, dict):
        return {k: (v[k] if k in ("$date", "$timestamp") else redact_value(v[k])) for k in v}
    return v


def maybe_redact(obj: Any, do_redact: bool) -> Any:
    return redact_value(obj) if do_redact else obj


def truncate(obj: Any, limit: int = 320) -> str:
    try:
        s = json.dumps(obj, default=str)
    except (TypeError, ValueError):
        s = str(obj)
    return s if len(s) <= limit else s[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def analyze(
    path: Path,
    *,
    min_duration_ms: int = 0,
    sample_limit: int | None = None,
    namespace_filter: str | None = None,
    redact: bool = False,
    catalog: IndexCatalog | None = None,
) -> AnalysisResult:
    result = AnalysisResult()
    ns_re = None
    if namespace_filter:
        # support glob-ish "db.*"
        ns_re = re.compile("^" + re.escape(namespace_filter).replace(r"\*", ".*") + "$")

    for line_no, raw, entry in iter_log_lines(path):
        result.total_lines += 1
        if entry is None:
            result.parse_errors += 1
            continue
        result.parsed_lines += 1

        if not is_slow_query(entry):
            continue
        result.slow_query_lines += 1

        event = extract_event(entry)
        if event is None:
            continue
        if event["duration_ms"] < min_duration_ms:
            continue

        ns = event["ns"]
        if not ns or ns.startswith(SKIP_DB_PREFIXES):
            result.skipped_namespace += 1
            continue
        if ns_re and not ns_re.match(ns):
            result.skipped_namespace += 1
            continue

        result.inspected_events += 1
        result.namespaces[ns] += 1
        if event["op_type"]:
            result.op_counts[event["op_type"]] += 1
        if event["err_name"]:
            result.error_codes_global[event["err_name"]] += 1
        if event["plan_summary"]:
            result.plan_summaries_global[event["plan_summary"]] += 1

        if not result.first_ts:
            result.first_ts = event["ts"]
        result.last_ts = event["ts"]

        # Aggregate by (queryHash, namespace)
        qh = event["query_hash"] or "NO_HASH"
        key = (qh, ns)
        shape = result.shapes.get(key)
        if shape is None:
            shape = QueryShape(
                query_hash=qh,
                plan_cache_key=event["plan_cache_key"],
                namespace=ns,
                op_type=event["op_type"],
            )
            result.shapes[key] = shape
            # Capture sample on first sighting only
            sample_filter_obj = event["filter"] or (event["pipeline"] or {})
            shape.sample_filter = truncate(maybe_redact(sample_filter_obj, redact))
            shape.sample_timestamp = event["ts"]
            try:
                pretty = json.dumps(maybe_redact(entry, redact), indent=2, default=str)
            except Exception:
                pretty = raw
            shape.sample_log_line = pretty
            detect(event, shape)
            # Resolve <TEXT_INDEXED_FIELD> placeholders using real index metadata.
            if shape.profile is not None:
                enrich_with_catalog(shape.profile, ns, catalog)

        shape.count += 1
        shape.total_duration_ms += event["duration_ms"]
        shape.max_duration_ms = max(shape.max_duration_ms, event["duration_ms"])
        shape.total_docs_examined += event["docs_examined"]
        shape.total_docs_returned += event["docs_returned"]
        shape.total_keys_examined += event["keys_examined"]
        if event["plan_summary"]:
            shape.plan_summaries[event["plan_summary"]] += 1
        if event["app_name"]:
            shape.app_names.add(event["app_name"])
        if event["err_name"]:
            shape.error_codes[event["err_name"]] += 1

        if sample_limit is not None and result.inspected_events >= sample_limit:
            break

    return result


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {"high": "#d9363e", "medium": "#e08e0b", "low": "#3a86ff"}

CSS = """
:root{--bg:#0f1115;--panel:#181b22;--panel2:#1f232c;--text:#e8e9ec;--muted:#9aa0aa;
      --border:#262a33;--accent:#00ed64;--accent2:#13aa52;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:var(--bg);color:var(--text);font-size:14px}
header{padding:24px 32px;border-bottom:1px solid var(--border);
       display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
header h1{margin:0;font-size:22px;font-weight:600}
header h1 span{color:var(--accent)}
header .meta{color:var(--muted);font-size:12px}
nav{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--border);
    padding:10px 32px;z-index:10;display:flex;gap:16px;flex-wrap:wrap}
nav a{color:var(--muted);text-decoration:none;font-size:13px;font-weight:500}
nav a:hover{color:var(--accent)}
main{padding:24px 32px 60px;max-width:1500px;margin:0 auto}
section{margin-bottom:36px}
h2{margin:0 0 12px;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.pills{display:flex;gap:8px;flex-wrap:wrap}
.pill{color:#fff;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card-num{font-size:24px;font-weight:700}
.card-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.two-col{grid-template-columns:1fr}}
.toolbar{display:flex;gap:10px;margin-bottom:8px;align-items:center;flex-wrap:wrap}
.toolbar input{background:var(--panel2);border:1px solid var(--border);color:var(--text);
               padding:6px 10px;border-radius:6px;font-size:13px;min-width:240px}
.toolbar select{background:var(--panel2);border:1px solid var(--border);color:var(--text);
                padding:6px 10px;border-radius:6px;font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--panel);
      border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{padding:9px 11px;text-align:left;border-bottom:1px solid var(--border);
      font-size:13px;vertical-align:top}
th{background:var(--panel2);color:var(--muted);text-transform:uppercase;font-size:11px;
   letter-spacing:.06em;cursor:pointer;user-select:none;position:sticky;top:0}
th:hover{color:var(--accent)}
tr:last-child td{border-bottom:none}
tr.expandable{cursor:pointer}
tr.expandable:hover td{background:#1a1f29}
tr.detail{display:none;background:#0d1016}
tr.detail.open{display:table-row}
tr.detail td{padding:14px 18px;color:var(--muted)}
code{background:#11141a;padding:1px 6px;border-radius:4px;font-size:12px}
pre{background:#0a0c12;padding:12px;border-radius:6px;margin:6px 0 0;
    overflow-x:auto;font-size:11.5px;white-space:pre-wrap;word-break:break-word;
    border:1px solid var(--border)}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:11px;
     font-weight:600;text-transform:uppercase}
.tag{display:inline-block;background:var(--panel2);border:1px solid var(--border);
     color:var(--text);padding:1px 6px;border-radius:4px;font-size:11px;margin-right:4px}
.suggest{background:#0c2418;border:1px solid #13aa52;border-radius:6px;
         padding:10px 12px;margin-top:8px;color:#cfeedd;font-size:12.5px}
.suggest b{color:var(--accent)}
.recommendation{margin-top:14px;background:#0a1812;border:1px solid #13aa52;
                border-radius:8px;padding:14px 16px}
.recommendation h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;
                   letter-spacing:.06em;color:var(--accent)}
.rec-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:1100px){.rec-grid{grid-template-columns:1fr}}
.rec-label{font-size:12px;color:var(--muted);text-transform:uppercase;
           letter-spacing:.05em;margin-bottom:6px}
.rec-code{background:#06100b;border:1px solid #13aa52;color:#d6f5e1;
          font-size:11.5px;line-height:1.5;max-height:340px;overflow:auto}
.rec-notes{margin-top:10px;font-size:12.5px;color:#bcd9c8}
.rec-notes ul{margin:6px 0 0;padding-left:20px}
.rec-notes li{margin:3px 0}
.muted{color:var(--muted)}
.right{text-align:right}
"""

JS = """
function bindSort(){
  document.querySelectorAll('table.sortable').forEach(t=>{
    const ths=t.querySelectorAll('th');
    ths.forEach((th,i)=>{
      th.addEventListener('click',()=>{
        const tbody=t.tBodies[0];
        const rows=Array.from(tbody.querySelectorAll('tr.row'));
        const dir=th.dataset.dir==='asc'?'desc':'asc';
        ths.forEach(x=>x.dataset.dir='');
        th.dataset.dir=dir;
        const num=th.dataset.type==='num';
        rows.sort((a,b)=>{
          let va=a.children[i].dataset.sort??a.children[i].innerText;
          let vb=b.children[i].dataset.sort??b.children[i].innerText;
          if(num){va=parseFloat(va)||0;vb=parseFloat(vb)||0;return dir==='asc'?va-vb:vb-va;}
          return dir==='asc'?String(va).localeCompare(vb):String(vb).localeCompare(va);
        });
        const detailMap=new Map();
        Array.from(tbody.querySelectorAll('tr.detail')).forEach(d=>detailMap.set(d.dataset.for,d));
        tbody.innerHTML='';
        rows.forEach(r=>{tbody.appendChild(r);const d=detailMap.get(r.dataset.id);if(d)tbody.appendChild(d);});
      });
    });
  });
}
function bindFilter(){
  document.querySelectorAll('input.filter').forEach(inp=>{
    inp.addEventListener('input',()=>{
      const t=document.querySelector(inp.dataset.target);
      const q=inp.value.toLowerCase();
      t.querySelectorAll('tr.row').forEach(r=>{
        const txt=r.innerText.toLowerCase();
        const show=txt.includes(q);
        r.style.display=show?'':'none';
        const d=t.querySelector(`tr.detail[data-for="${r.dataset.id}"]`);
        if(d)d.style.display=show&&d.classList.contains('open')?'table-row':'none';
      });
    });
  });
}
function bindSeverityFilter(){
  document.querySelectorAll('select.sevfilter').forEach(sel=>{
    sel.addEventListener('change',()=>{
      const t=document.querySelector(sel.dataset.target);
      const v=sel.value;
      t.querySelectorAll('tr.row').forEach(r=>{
        const sv=r.dataset.severity||'';
        const show=!v||sv===v;
        r.style.display=show?'':'none';
      });
    });
  });
}
function bindExpand(){
  document.querySelectorAll('tr.expandable').forEach(r=>{
    r.addEventListener('click',()=>{
      const d=document.querySelector(`tr.detail[data-for="${r.dataset.id}"]`);
      if(d)d.classList.toggle('open');
    });
  });
}
function expandAll(t,open){
  document.querySelectorAll(t+' tr.detail').forEach(d=>d.classList.toggle('open',open));
}
document.addEventListener('DOMContentLoaded',()=>{bindSort();bindFilter();bindSeverityFilter();bindExpand();});
"""


def render_html(result: AnalysisResult, source: Path, args,
                catalog: IndexCatalog | None = None) -> str:
    shapes = list(result.shapes.values())
    # Only opportunities (have at least one Atlas Search category)
    opportunities = [s for s in shapes if s.categories]
    opportunities.sort(key=lambda s: (SEVERITY_RANK[s.severity], -s.total_duration_ms, -s.count))

    # Aggregate counts
    cat_counts: Counter = Counter()
    sev_counts: Counter = Counter()
    for s in opportunities:
        sev_counts[s.severity] += 1
        for c in s.categories:
            cat_counts[c] += 1

    ns_counts: Counter = Counter()
    for s in opportunities:
        ns_counts[s.namespace] += s.count

    # Cards
    cards_data = [
        ("Total log lines", f"{result.total_lines:,}"),
        ("Parsed JSON lines", f"{result.parsed_lines:,}"),
        ("Slow-query events", f"{result.slow_query_lines:,}"),
        ("Inspected (post-filter)", f"{result.inspected_events:,}"),
        ("Distinct query shapes", f"{len(shapes):,}"),
        ("Atlas Search opportunities", f"{len(opportunities):,}"),
        ("Namespaces", f"{len(result.namespaces):,}"),
        ("Window", _ts_window(result.first_ts, result.last_ts)),
    ]
    if catalog is not None:
        drop_list = catalog.drop_candidates()
        cards_data.extend([
            ("Indexes loaded", f"{len(catalog.entries):,}"),
            ("Total index size", f"{catalog.total_size_mb():,.1f} MB"),
            ("Drop candidates", f"{len(drop_list):,}"),
            ("Reclaimable", f"{catalog.total_drop_size_mb():,.1f} MB"),
        ])
    cards_html = "".join(
        f'<div class="card"><div class="card-num">{escape(v)}</div>'
        f'<div class="card-label">{escape(k)}</div></div>'
        for k, v in cards_data
    )

    sev_pills = "".join(
        f'<span class="pill" style="background:{SEVERITY_COLOR[s]}">'
        f'{s.upper()}: {sev_counts.get(s,0)}</span>'
        for s in ("high", "medium", "low")
    )

    cat_table = "".join(
        f'<tr class="row"><td>{escape(CATEGORY_LABEL.get(c,c))}</td>'
        f'<td class="right" data-sort="{n}">{n}</td></tr>'
        for c, n in cat_counts.most_common()
    ) or '<tr><td colspan=2 class="muted">No findings.</td></tr>'

    ns_table = "".join(
        f'<tr class="row"><td><code>{escape(ns)}</code></td>'
        f'<td class="right" data-sort="{n}">{n}</td></tr>'
        for ns, n in ns_counts.most_common(20)
    ) or '<tr><td colspan=2 class="muted">No findings.</td></tr>'

    op_table = "".join(
        f'<tr class="row"><td><code>{escape(op or "?")}</code></td>'
        f'<td class="right" data-sort="{n}">{n:,}</td></tr>'
        for op, n in result.op_counts.most_common()
    ) or '<tr><td colspan=2 class="muted">None.</td></tr>'

    err_table = "".join(
        f'<tr class="row"><td><code>{escape(e)}</code></td>'
        f'<td class="right" data-sort="{n}">{n:,}</td></tr>'
        for e, n in result.error_codes_global.most_common(15)
    ) or '<tr><td colspan=2 class="muted">No errors logged.</td></tr>'

    plan_table = "".join(
        f'<tr class="row"><td><code>{escape(p)}</code></td>'
        f'<td class="right" data-sort="{n}">{n:,}</td></tr>'
        for p, n in result.plan_summaries_global.most_common(15)
    ) or '<tr><td colspan=2 class="muted">No planSummaries.</td></tr>'

    # Opportunity rows
    opp_rows = "\n".join(_render_opp_row(i, s, catalog) for i, s in enumerate(opportunities)) \
        or '<tr><td colspan="9" class="muted" style="text-align:center;padding:24px">No Atlas Search opportunities detected.</td></tr>'

    # All shapes (for full visibility)
    all_shapes_sorted = sorted(shapes, key=lambda s: -s.total_duration_ms)[:200]
    all_rows = "\n".join(_render_shape_row(i, s) for i, s in enumerate(all_shapes_sorted)) \
        or '<tr><td colspan="8" class="muted">None.</td></tr>'

    # Index inventory & drop candidates (only when catalog is supplied)
    index_section = _render_index_section(catalog) if catalog else ""
    drop_section = _render_drop_section(catalog) if catalog else ""
    index_nav = ('<a href="#indexes">Indexes</a>'
                 '<a href="#drops">Drop Candidates</a>') if catalog else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Atlas Search Opportunity Report — {escape(source.name)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <div>
    <h1>Atlas Search Opportunity <span>Report</span></h1>
    <div class="meta">Source: <code>{escape(str(source))}</code> · Window: {escape(_ts_window(result.first_ts, result.last_ts))}
        · Generated {escape(datetime.now(timezone.utc).isoformat(timespec='seconds'))}</div>
  </div>
  <div class="pills">{sev_pills}</div>
</header>

<nav>
  <a href="#summary">Summary</a>
  <a href="#opps">Atlas Search Opportunities</a>
  <a href="#shapes">All Query Shapes</a>
  <a href="#namespaces">Namespaces</a>
  <a href="#ops">Operations</a>
  <a href="#plans">Plan Summaries</a>
  <a href="#errors">Errors</a>
  {index_nav}
  <a href="#tasks">Migration Tasks</a>
</nav>

<main>
  <section id="summary">
    <h2>Summary</h2>
    <div class="grid">{cards_html}</div>
  </section>

  <section id="opps">
    <h2>Atlas Search Opportunities &nbsp;<span class="muted">({len(opportunities)} distinct query shapes)</span></h2>
    <div class="toolbar">
      <input class="filter" data-target="#opp-table" placeholder="Filter (namespace, category, hash, app)…" />
      <select class="sevfilter" data-target="#opp-table">
        <option value="">All severities</option>
        <option value="high">High only</option>
        <option value="medium">Medium only</option>
        <option value="low">Low only</option>
      </select>
      <button onclick="expandAll('#opp-table',true)">Expand all</button>
      <button onclick="expandAll('#opp-table',false)">Collapse all</button>
    </div>
    <table id="opp-table" class="sortable">
      <thead><tr>
        <th>Severity</th><th>Categories</th><th>Namespace</th><th>QueryHash</th>
        <th data-type="num" class="right">Count</th>
        <th data-type="num" class="right">Total ms</th>
        <th data-type="num" class="right">Avg ms</th>
        <th data-type="num" class="right">Docs/Ret</th>
        <th>Plan</th>
      </tr></thead>
      <tbody>{opp_rows}</tbody>
    </table>
  </section>

  <section id="shapes">
    <h2>All Query Shapes <span class="muted">(top 200 by total duration)</span></h2>
    <div class="toolbar">
      <input class="filter" data-target="#all-table" placeholder="Filter…" />
    </div>
    <table id="all-table" class="sortable">
      <thead><tr>
        <th>Namespace</th><th>Op</th><th>QueryHash</th>
        <th data-type="num" class="right">Count</th>
        <th data-type="num" class="right">Total ms</th>
        <th data-type="num" class="right">Max ms</th>
        <th data-type="num" class="right">Keys/Ret</th>
        <th>Plan</th>
      </tr></thead>
      <tbody>{all_rows}</tbody>
    </table>
  </section>

  <div class="two-col">
    <section id="namespaces">
      <h2>Top Namespaces (in opportunities)</h2>
      <table class="sortable"><thead><tr><th>Namespace</th><th data-type="num" class="right">Findings</th></tr></thead>
        <tbody>{ns_table}</tbody></table>
    </section>
    <section>
      <h2>Categories</h2>
      <table class="sortable"><thead><tr><th>Category</th><th data-type="num" class="right">Shapes</th></tr></thead>
        <tbody>{cat_table}</tbody></table>
    </section>
  </div>

  <div class="two-col">
    <section id="ops">
      <h2>Operations</h2>
      <table class="sortable"><thead><tr><th>Op type</th><th data-type="num" class="right">Events</th></tr></thead>
        <tbody>{op_table}</tbody></table>
    </section>
    <section id="plans">
      <h2>Plan Summaries</h2>
      <table class="sortable"><thead><tr><th>planSummary</th><th data-type="num" class="right">Events</th></tr></thead>
        <tbody>{plan_table}</tbody></table>
    </section>
  </div>

  <section id="errors">
    <h2>Error Codes</h2>
    <table class="sortable"><thead><tr><th>errName</th><th data-type="num" class="right">Events</th></tr></thead>
      <tbody>{err_table}</tbody></table>
  </section>

  {drop_section}
  {index_section}

  <section id="tasks">
    <h2>Migration Task Checklist</h2>
    {_render_tasks(opportunities)}
  </section>
</main>

<script>{JS}</script>
</body></html>"""


def _render_opp_row(i: int, s: QueryShape, catalog: IndexCatalog | None = None) -> str:
    cats_html = "".join(
        f'<span class="tag">{escape(CATEGORY_LABEL.get(c,c))}</span>'
        for c in sorted(s.categories)
    )
    plan = ", ".join(p for p, _ in s.plan_summaries.most_common(2)) or "-"
    avg = s.avg_duration_ms()
    dpr = s.docs_per_returned()
    apps = ", ".join(sorted(s.app_names)) if s.app_names else "-"
    suggestions = "".join(
        f'<div class="suggest"><b>{escape(CATEGORY_LABEL.get(c,c))}:</b> {escape(ATLAS_SUGGESTION.get(c,""))}</div>'
        for c in sorted(s.categories)
    )
    rid = f"opp-{i}"
    recommendation_html = _render_recommendation(s, catalog)
    return (
        f'<tr class="row expandable" data-id="{rid}" data-severity="{s.severity}">'
        f'<td><span class="sev" style="background:{SEVERITY_COLOR[s.severity]}">{s.severity}</span></td>'
        f'<td>{cats_html}</td>'
        f'<td><code>{escape(s.namespace)}</code></td>'
        f'<td><code>{escape(s.query_hash)}</code></td>'
        f'<td class="right" data-sort="{s.count}">{s.count:,}</td>'
        f'<td class="right" data-sort="{s.total_duration_ms}">{s.total_duration_ms:,}</td>'
        f'<td class="right" data-sort="{avg:.1f}">{avg:,.1f}</td>'
        f'<td class="right" data-sort="{dpr:.1f}">{dpr:,.1f}</td>'
        f'<td><code>{escape(plan)}</code></td>'
        f'</tr>'
        f'<tr class="detail" data-for="{rid}"><td colspan="9">'
        f'<div><b>App:</b> {escape(apps)} &nbsp; <b>Op:</b> <code>{escape(s.op_type or "?")}</code> '
        f'&nbsp; <b>planCacheKey:</b> <code>{escape(s.plan_cache_key or "-")}</code> '
        f'&nbsp; <b>First seen:</b> {escape(s.sample_timestamp or "-")}</div>'
        f'<div style="margin-top:6px"><b>Reasons:</b><ul>'
        + "".join(f"<li>{escape(r)}</li>" for r in s.reasons) +
        f'</ul></div>'
        f'{suggestions}'
        f'<div style="margin-top:10px"><b>Sample filter:</b><pre>{escape(s.sample_filter)}</pre></div>'
        f'{recommendation_html}'
        f'<details style="margin-top:8px"><summary class="muted">Raw log line</summary>'
        f'<pre>{escape(s.sample_log_line)}</pre></details>'
        f'</td></tr>'
    )


def _render_recommendation(s: QueryShape, catalog: IndexCatalog | None = None) -> str:
    """Render the Atlas Search index + $search pipeline recommendation block."""
    if not s.profile:
        return ""

    index_def = build_index_definition(s.profile, name="default")
    pipeline = build_search_pipeline(s.profile, index_name="default")
    notes = build_notes(s.profile)

    notes_html = "".join(f"<li>{escape(n)}</li>" for n in notes)
    coll = s.profile.collection or s.namespace.split(".", 1)[-1]

    # If a catalog is loaded, list existing indexes whose fields are a subset of
    # the proposed Atlas Search index — informational only (conservative policy).
    replaces_html = ""
    if catalog is not None:
        replaced = find_replaced_indexes(s.profile, s.namespace, catalog)
        if replaced:
            items = []
            for e in sorted(replaced, key=lambda x: -x.size_mb):
                key_html = escape(", ".join(f"{k}:{v}" for k, v in e.key.items()))
                items.append(
                    f'<li><code>{escape(e.name)}</code> — '
                    f'<span class="muted">{key_html}</span> &nbsp; '
                    f'<span class="muted">({e.size_mb:.1f} MB · '
                    f'{e.total_ops:,} ops</span>'
                    + (' · <b style="color:#e08e0b">duplicate</b>' if e.is_duplicate else '')
                    + (' · <b style="color:#e08e0b">unused</b>' if e.is_unused else '')
                    + ')</li>'
                )
            replaces_html = (
                f'<div class="rec-notes" style="border-top:1px solid #13aa52;'
                f'padding-top:8px;margin-top:10px">'
                f'<b>Existing indexes potentially replaced after Atlas Search cutover '
                f'({len(replaced)}):</b><ul>{"".join(items)}</ul>'
                f'<div class="muted" style="margin-top:4px">Conservative policy: '
                f'<b>do not drop these</b> until the Atlas Search index is built and '
                f'verified in production. See the Drop Candidates section for indexes '
                f'safe to drop immediately.</div>'
                f'</div>'
            )

    return (
        f'<div class="recommendation">'
        f'<h3>Suggested Atlas Search migration</h3>'
        f'<div class="rec-grid">'
        f'<div>'
        f'<div class="rec-label">1. Atlas Search index definition'
        f' <span class="muted">(create on collection <code>{escape(coll)}</code>)</span></div>'
        f'<pre class="rec-code">{escape(to_pretty_json(index_def))}</pre>'
        f'</div>'
        f'<div>'
        f'<div class="rec-label">2. Replacement aggregation pipeline</div>'
        f'<pre class="rec-code">{escape(to_pretty_json(pipeline))}</pre>'
        f'</div>'
        f'</div>'
        f'<div class="rec-notes"><b>Notes:</b><ul>{notes_html}</ul></div>'
        f'{replaces_html}'
        f'</div>'
    )


def _render_shape_row(i: int, s: QueryShape) -> str:
    plan = ", ".join(p for p, _ in s.plan_summaries.most_common(2)) or "-"
    kpr = (s.total_keys_examined / s.total_docs_returned) if s.total_docs_returned else 0
    return (
        f'<tr class="row" data-id="all-{i}">'
        f'<td><code>{escape(s.namespace)}</code></td>'
        f'<td><code>{escape(s.op_type or "?")}</code></td>'
        f'<td><code>{escape(s.query_hash)}</code></td>'
        f'<td class="right" data-sort="{s.count}">{s.count:,}</td>'
        f'<td class="right" data-sort="{s.total_duration_ms}">{s.total_duration_ms:,}</td>'
        f'<td class="right" data-sort="{s.max_duration_ms}">{s.max_duration_ms:,}</td>'
        f'<td class="right" data-sort="{kpr:.1f}">{kpr:,.1f}</td>'
        f'<td><code>{escape(plan)}</code></td>'
        f'</tr>'
    )


def _render_drop_section(catalog: IndexCatalog | None) -> str:
    """List indexes that are safe to drop right now (duplicates + zero-ops)."""
    if catalog is None:
        return ""
    drops = sorted(catalog.drop_candidates(), key=lambda e: (-e.size_mb, e.namespace, e.name))
    if not drops:
        return (
            '<section id="drops"><h2>Drop Candidates</h2>'
            '<p class="muted">No safe drop candidates found '
            '(no duplicates, no zero-op indexes).</p></section>'
        )

    rows: list[str] = []
    for e in drops:
        reason = e.drop_candidate or ""
        key_str = ", ".join(f"{k}:{v}" for k, v in e.key.items()) or "-"
        tag = '<span class="tag" style="background:#3a1a1d;border-color:#d9363e;color:#ffb1b6">duplicate</span>' \
            if e.is_duplicate else \
            '<span class="tag" style="background:#3a2a1a;border-color:#e08e0b;color:#ffd07a">unused</span>'
        rows.append(
            f'<tr class="row">'
            f'<td>{tag}</td>'
            f'<td><code>{escape(e.namespace)}</code></td>'
            f'<td><code>{escape(e.name)}</code></td>'
            f'<td><code class="muted">{escape(key_str)}</code></td>'
            f'<td class="right" data-sort="{e.size_mb}">{e.size_mb:,.1f}</td>'
            f'<td class="right" data-sort="{e.total_ops}">{e.total_ops:,}</td>'
            f'<td class="muted">{escape(reason)}</td>'
            f'</tr>'
        )
    total_mb = sum(e.size_mb for e in drops)
    return (
        f'<section id="drops">'
        f'<h2>Drop Candidates &nbsp;<span class="muted">'
        f'({len(drops)} indexes, ~{total_mb:,.1f} MB reclaimable)</span></h2>'
        f'<div class="toolbar">'
        f'<input class="filter" data-target="#drop-table" placeholder="Filter (namespace, name, key)…" />'
        f'</div>'
        f'<table id="drop-table" class="sortable"><thead><tr>'
        f'<th>Why</th><th>Namespace</th><th>Name</th><th>Key</th>'
        f'<th data-type="num" class="right">Size (MB)</th>'
        f'<th data-type="num" class="right">Total Ops</th><th>Reason</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
        f'</section>'
    )


def _render_index_section(catalog: IndexCatalog | None) -> str:
    """Full index inventory table grouped by namespace, sortable & filterable."""
    if catalog is None:
        return ""
    if not catalog.entries:
        return ('<section id="indexes"><h2>Index Inventory</h2>'
                '<p class="muted">No index entries parsed from CSV.</p></section>')

    entries = sorted(catalog.entries, key=lambda e: (-e.size_mb, e.namespace, e.name))
    rows: list[str] = []
    for e in entries:
        key_str = ", ".join(f"{k}:{v}" for k, v in e.key.items()) or "-"
        flags = []
        if e.is_text_index:
            flags.append('<span class="tag" style="background:#0c2418;border-color:#13aa52;color:#a0e7c0">text</span>')
        if e.is_duplicate:
            flags.append('<span class="tag" style="background:#3a1a1d;border-color:#d9363e;color:#ffb1b6">dup</span>')
        if e.is_unused:
            flags.append('<span class="tag" style="background:#3a2a1a;border-color:#e08e0b;color:#ffd07a">unused</span>')
        rows.append(
            f'<tr class="row">'
            f'<td><code>{escape(e.namespace)}</code></td>'
            f'<td><code>{escape(e.name)}</code></td>'
            f'<td>{escape(e.display_type)}</td>'
            f'<td><code class="muted">{escape(key_str)}</code></td>'
            f'<td class="right" data-sort="{e.size_mb}">{e.size_mb:,.1f}</td>'
            f'<td class="right" data-sort="{e.primary_ops}">{e.primary_ops:,}</td>'
            f'<td class="right" data-sort="{e.secondary_ops}">{e.secondary_ops:,}</td>'
            f'<td>{" ".join(flags)}</td>'
            f'</tr>'
        )
    return (
        f'<section id="indexes">'
        f'<h2>Index Inventory &nbsp;<span class="muted">({len(entries):,} indexes, '
        f'{catalog.total_size_mb():,.1f} MB total)</span></h2>'
        f'<div class="toolbar">'
        f'<input class="filter" data-target="#index-table" placeholder="Filter (namespace, name, key, type)…" />'
        f'</div>'
        f'<table id="index-table" class="sortable"><thead><tr>'
        f'<th>Namespace</th><th>Name</th><th>Type</th><th>Key</th>'
        f'<th data-type="num" class="right">Size (MB)</th>'
        f'<th data-type="num" class="right">Primary Ops</th>'
        f'<th data-type="num" class="right">Secondary Ops</th>'
        f'<th>Flags</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
        f'</section>'
    )


def _render_tasks(opportunities: list[QueryShape]) -> str:
    """Concrete migration task list grouped by category and namespace."""
    if not opportunities:
        return '<p class="muted">No tasks — log shows no Atlas Search opportunities.</p>'

    # group: category -> namespace -> [shapes]
    grouped: dict[str, dict[str, list[QueryShape]]] = defaultdict(lambda: defaultdict(list))
    for s in opportunities:
        for c in s.categories:
            grouped[c][s.namespace].append(s)

    cat_order = sorted(grouped.keys(),
                       key=lambda c: -sum(len(v) for v in grouped[c].values()))

    out = ['<ol style="padding-left:20px;line-height:1.7">']
    for c in cat_order:
        out.append(f'<li><b>{escape(CATEGORY_LABEL.get(c,c))}</b>')
        out.append(f'<div class="suggest" style="margin:6px 0 8px">{escape(ATLAS_SUGGESTION.get(c,""))}</div>')
        out.append('<ul>')
        for ns, items in sorted(grouped[c].items(), key=lambda kv: -sum(s.count for s in kv[1])):
            total = sum(s.count for s in items)
            ms = sum(s.total_duration_ms for s in items)
            hashes = ", ".join(sorted({s.query_hash for s in items if s.query_hash and s.query_hash != "NO_HASH"})[:6])
            out.append(
                f'<li><code>{escape(ns)}</code> — {len(items)} query shape(s), '
                f'{total:,} hits, {ms:,} ms total. '
                f'<span class="muted">queryHash: {escape(hashes) or "-"}</span></li>'
            )
        out.append('</ul></li>')
    out.append('</ol>')
    return "\n".join(out)


def _ts_window(first: str, last: str) -> str:
    if not first and not last:
        return "—"
    if first == last:
        return first or "—"
    return f"{first or '?'} → {last or '?'}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Identify MongoDB Atlas Search migration opportunities from mongod structured logs."
    )
    p.add_argument("log", type=Path, help="Path to a MongoDB structured JSON log file (.log or .gz)")
    p.add_argument("--out", type=Path, default=Path("atlas_search_report.html"),
                   help="Output HTML report path (default: atlas_search_report.html)")
    p.add_argument("--min-duration", type=int, default=0,
                   help="Ignore slow-query events faster than this many ms (default: 0)")
    p.add_argument("--sample", type=int, default=None,
                   help="Stop after N inspected slow-query events (smoke-test mode)")
    p.add_argument("--ns", type=str, default=None,
                   help="Limit to a namespace; supports glob, e.g. 'FalconFlexTripsSvcProd.*'")
    p.add_argument("--redact", action="store_true",
                   help="Redact string/numeric values in the report (production-safe sharing)")
    p.add_argument("--indexes", type=Path, default=None,
                   help="CSV dump of cluster indexes (DB, Collection, Name, Type, Size, Ops, Key, …). "
                        "If omitted, auto-detect 'indexes.csv' next to the log file.")
    args = p.parse_args(argv)

    if not args.log.exists():
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        return 2

    # Resolve index catalog: explicit flag wins; otherwise auto-detect.
    catalog: IndexCatalog | None = None
    index_path = args.indexes
    if index_path is None:
        auto = args.log.parent / "indexes.csv"
        if auto.exists():
            index_path = auto
    if index_path is not None:
        if not index_path.exists():
            print(f"error: index CSV not found: {index_path}", file=sys.stderr)
            return 2
        catalog = load_catalog(index_path)
        print(f"Indexes:       loaded {len(catalog.entries):,} entries from {index_path} "
              f"({catalog.parse_errors:,} parse errors)", file=sys.stderr)

    print(f"Analyzing {args.log} (size={_human(args.log.stat().st_size)})…", file=sys.stderr)
    if args.sample:
        print(f"  sample mode: stop after {args.sample:,} inspected events", file=sys.stderr)

    result = analyze(
        args.log,
        min_duration_ms=args.min_duration,
        sample_limit=args.sample,
        namespace_filter=args.ns,
        redact=args.redact,
        catalog=catalog,
    )
    html = render_html(result, args.log, args, catalog=catalog)
    args.out.write_text(html, encoding="utf-8")

    print(f"\nLog lines:     {result.total_lines:,} total, {result.parsed_lines:,} JSON, "
          f"{result.parse_errors:,} parse errors", file=sys.stderr)
    print(f"Slow queries:  {result.slow_query_lines:,} found, "
          f"{result.inspected_events:,} inspected, {result.skipped_namespace:,} skipped (ns filter)", file=sys.stderr)
    print(f"Query shapes:  {len(result.shapes):,} distinct "
          f"({sum(1 for s in result.shapes.values() if s.categories):,} with Atlas Search opportunities)",
          file=sys.stderr)
    print(f"Report:        {args.out.resolve()}", file=sys.stderr)
    return 0


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


if __name__ == "__main__":
    raise SystemExit(main())
