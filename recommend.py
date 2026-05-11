"""
Atlas Search recommendation engine.
====================================

Given a `QueryProfile` extracted while parsing a slow-query event, synthesize:

  1. A suggested Atlas Search **index definition** (JSON).
  2. A suggested **$search aggregation pipeline** that replaces the original
     query while preserving sort / pagination / equality filters.

Both outputs are intended to be copy-paste-into-Atlas-UI ready, but the user
should review analyzer/field-type choices before deploying.

References:
  - https://www.mongodb.com/docs/atlas/atlas-search/index-definitions/
  - https://www.mongodb.com/docs/atlas/atlas-search/compound/
  - https://www.mongodb.com/docs/atlas/atlas-search/text/
  - https://www.mongodb.com/docs/atlas/atlas-search/autocomplete/
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from indexes import IndexCatalog, IndexEntry


# ---------------------------------------------------------------------------
# Profile captured during detection
# ---------------------------------------------------------------------------

@dataclass
class QueryProfile:
    """Structured shape of a single slow query, used to synthesize an Atlas Search
    index + rewritten $search pipeline."""

    op_type: str = ""                                  # find / aggregate / ...
    collection: str = ""                                # collection name only
    # Field roles
    text_fields: set[str] = field(default_factory=set)  # fields with $text/$regex/string-equality "search" intent
    autocomplete_fields: set[str] = field(default_factory=set)  # leading-wildcard regex => prefix/edgeGram
    equality_fields: dict[str, object] = field(default_factory=dict)   # {field: sample_value} for compound.filter
    range_fields: set[str] = field(default_factory=set)  # fields with $gte/$lte/$gt/$lt
    sort_fields: list[tuple[str, int]] = field(default_factory=list)   # [(field, 1|-1), …]
    # Raw search terms recovered
    text_query: str | None = None       # search string from $text.$search
    regex_patterns: list[tuple[str, str]] = field(default_factory=list)  # [(field, pattern)]
    or_text_fields: set[str] = field(default_factory=set)
    # Pagination
    limit: int | None = None
    skip: int | None = None
    # Misc
    case_insensitive: bool = False


# ---------------------------------------------------------------------------
# Catalog-aware enrichment
# ---------------------------------------------------------------------------

def enrich_with_catalog(profile: QueryProfile,
                         namespace: str,
                         catalog: "IndexCatalog | None") -> None:
    """Mutate `profile` in place using actual index metadata.

    Currently resolves the <TEXT_INDEXED_FIELD> placeholder by reading the
    weighted field names from any text index on the namespace.
    """
    if catalog is None:
        return
    if "<TEXT_INDEXED_FIELD>" not in profile.text_fields:
        return
    real_fields = catalog.text_index_fields(namespace)
    if real_fields:
        profile.text_fields.discard("<TEXT_INDEXED_FIELD>")
        profile.text_fields.update(real_fields)


def find_replaced_indexes(profile: QueryProfile,
                           namespace: str,
                           catalog: "IndexCatalog | None") -> list["IndexEntry"]:
    """Return existing indexes whose key fields are a subset of the proposed
    Atlas Search index's fields.

    These are informational ("after Atlas Search cutover, these indexes are
    potentially redundant") — *not* automatic drop recommendations.
    """
    if catalog is None:
        return []
    proposed_fields = (
        profile.text_fields
        | profile.or_text_fields
        | profile.autocomplete_fields
        | set(profile.equality_fields.keys())
        | profile.range_fields
        | {f for f, _ in profile.sort_fields}
    )
    # Don't claim to replace indexes on placeholder fields
    proposed_fields = {f for f in proposed_fields if not f.startswith("<")}
    if not proposed_fields:
        return []
    return [e for e in catalog.covering_indexes(namespace, proposed_fields)
            if e.name != "_id_"]


# ---------------------------------------------------------------------------
# Index synthesizer
# ---------------------------------------------------------------------------

def build_index_definition(profile: QueryProfile, name: str = "default") -> dict:
    """Produce an Atlas Search index definition (mappings.fields) for the profile.

    Strategy: `dynamic: false` and one explicit field entry per role. This is
    safer (smaller index, predictable) than `dynamic: true`.
    """
    fields: dict[str, list[dict] | dict] = {}

    def add(field_name: str, mapping: dict) -> None:
        existing = fields.get(field_name)
        if existing is None:
            fields[field_name] = mapping
        elif isinstance(existing, list):
            if mapping not in existing:
                existing.append(mapping)
        else:
            if existing != mapping:
                fields[field_name] = [existing, mapping]

    # Text-searchable fields → standard analyzer
    for f in sorted(profile.text_fields | profile.or_text_fields):
        add(f, {"type": "string", "analyzer": "lucene.standard"})

    # Autocomplete fields (leading-wildcard regex / "type-ahead")
    for f in sorted(profile.autocomplete_fields):
        add(f, {
            "type": "autocomplete",
            "tokenization": "edgeGram",
            "minGrams": 2,
            "maxGrams": 15,
            "foldDiacritics": True,
        })

    # Equality / filter fields → token analyzer (exact match, low cardinality friendly)
    for f, sample in profile.equality_fields.items():
        if isinstance(sample, bool):
            add(f, {"type": "boolean"})
        elif isinstance(sample, (int, float)):
            add(f, {"type": "number"})
        elif isinstance(sample, dict) and "$date" in sample:
            add(f, {"type": "date"})
        else:
            add(f, {"type": "token", "normalizer": "lowercase"})

    # Range fields → typed (assume numeric/date; if unknown, still emit number+date)
    for f in sorted(profile.range_fields):
        add(f, {"type": "date"})  # most common in MongoDB slow-query patterns
        # If it turns out to be numeric, the user can change to "number".

    # Sort fields → must be indexed; for strings use token
    for f, _direction in profile.sort_fields:
        if f not in fields:
            add(f, {"type": "date"})  # heuristic: sort fields are usually dates/numbers

    return {
        "name": name,
        "mappings": {
            "dynamic": False,
            "fields": fields,
        },
    }


# ---------------------------------------------------------------------------
# $search pipeline rewriter
# ---------------------------------------------------------------------------

def build_search_pipeline(profile: QueryProfile, index_name: str = "default") -> list[dict]:
    """Produce a replacement aggregation pipeline beginning with `$search`.

    Layout:

        [
          { "$search": {
              "index": "<name>",
              "compound": {
                "must":   [ <text/regex/autocomplete clause> ],
                "filter": [ <equality + range clauses> ],
                "should": [ <or branches> ]
              }
          }},
          { "$match": <residual filters that don't map cleanly> },     # rare
          { "$sort":  ... },
          { "$skip":  ... },
          { "$limit": ... }
        ]
    """
    must: list[dict] = []
    should: list[dict] = []
    filt: list[dict] = []

    # --- text / search-bar intent ---------------------------------------------
    text_paths = sorted(profile.text_fields | profile.or_text_fields)
    if profile.text_query and text_paths:
        must.append({
            "text": {
                "query": profile.text_query,
                "path": text_paths if len(text_paths) > 1 else text_paths[0],
            }
        })
    elif profile.regex_patterns:
        for fname, pat in profile.regex_patterns:
            if fname in profile.autocomplete_fields:
                must.append({
                    "autocomplete": {
                        "query": _strip_regex_anchors(pat),
                        "path": fname,
                    }
                })
            else:
                must.append({
                    "wildcard": {
                        "query": _regex_to_wildcard(pat),
                        "path": fname,
                        "allowAnalyzedField": True,
                    }
                })
    elif profile.or_text_fields and not profile.text_query:
        # $or pattern without a single search term — emit `compound.should`
        # placeholder the user fills in.
        for f in sorted(profile.or_text_fields):
            should.append({
                "text": {
                    "query": "<USER_SEARCH_TERM>",
                    "path": f,
                }
            })

    # --- equality filters ------------------------------------------------------
    for fname, sample in profile.equality_fields.items():
        if isinstance(sample, dict) and "$oid" in sample:
            # ObjectId comparison stays as $match — Atlas Search doesn't index ObjectId well
            continue
        filt.append({
            "equals": {
                "path": fname,
                "value": sample,
            }
        })

    # --- range filters ---------------------------------------------------------
    for fname in sorted(profile.range_fields):
        filt.append({
            "range": {
                "path": fname,
                "gte": "<START>",
                "lte": "<END>",
            }
        })

    # Build the compound clause
    compound: dict[str, list[dict]] = {}
    if must:
        compound["must"] = must
    if filt:
        compound["filter"] = filt
    if should:
        compound["should"] = should
        compound["minimumShouldMatch"] = 1

    if not compound:
        # Pure search-bar with unknown term — emit a representative shell
        compound = {
            "must": [{
                "text": {
                    "query": "<USER_SEARCH_TERM>",
                    "path": text_paths or "<FIELD>",
                }
            }],
        }

    pipeline: list[dict] = [{
        "$search": {
            "index": index_name,
            "compound": compound,
        }
    }]

    if profile.sort_fields:
        pipeline.append({"$sort": {f: d for f, d in profile.sort_fields}})
    if profile.skip:
        pipeline.append({"$skip": profile.skip})
    if profile.limit:
        pipeline.append({"$limit": profile.limit})

    return pipeline


# ---------------------------------------------------------------------------
# Notes — human-readable caveats per recommendation
# ---------------------------------------------------------------------------

def build_notes(profile: QueryProfile) -> list[str]:
    notes: list[str] = []

    if profile.text_query:
        notes.append(
            "The `text` operator uses the index's analyzer at query time. If the "
            "captured query was a phrase (e.g. quoted), use the `phrase` operator "
            "instead for exact-phrase semantics."
        )

    if profile.autocomplete_fields:
        notes.append(
            "`autocomplete` uses edgeGram tokenization (prefix matching). For "
            "infix matching (matching anywhere in the token), switch to the "
            "`wildcard` operator with `allowAnalyzedField: true`, or use `nGram` "
            "tokenization on the autocomplete field."
        )

    if profile.case_insensitive and not profile.autocomplete_fields:
        notes.append(
            "Case-insensitivity is handled by the `lowercase` token filter "
            "(included in `lucene.standard`). No collation needed."
        )

    if profile.or_text_fields and not profile.text_query:
        notes.append(
            "Replace `<USER_SEARCH_TERM>` with the actual search-bar input. "
            "`compound.should` ranks documents by how many fields match; "
            "set `minimumShouldMatch: 1` to require at least one."
        )

    if profile.sort_fields:
        notes.append(
            "Sort applied *after* `$search`. To sort by relevance instead, "
            "remove the `$sort` stage and use Atlas Search's default scoring."
        )

    if any(isinstance(v, dict) and "$oid" in v for v in profile.equality_fields.values()):
        notes.append(
            "ObjectId equality filters are kept as a regular `$match` stage "
            "downstream of `$search` — Atlas Search's `equals` operator works "
            "best on tokens/numbers/dates/booleans."
        )

    notes.append(
        "Review analyzer choices and field types before deploying. Consider a "
        "language-specific analyzer (e.g. `lucene.english`) if your data is "
        "predominantly one language."
    )
    return notes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_regex_anchors(pat: str) -> str:
    """Best-effort: turn `/^foo/` or `/.*foo.*/` into a plain `foo` query."""
    if not isinstance(pat, str):
        return ""
    s = pat
    if s.startswith("^"):
        s = s[1:]
    if s.endswith("$"):
        s = s[:-1]
    s = s.replace(".*", "").replace(".+", "")
    # Strip leading/trailing wildcards we removed
    return s.strip()


def _regex_to_wildcard(pat: str) -> str:
    """Convert a MongoDB regex pattern to Atlas Search wildcard syntax (* and ?)."""
    if not isinstance(pat, str):
        return ""
    s = pat
    if s.startswith("^"):
        s = s[1:]
    if s.endswith("$"):
        s = s[:-1]
    s = s.replace(".*", "*").replace(".", "?")
    return s


def to_pretty_json(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
