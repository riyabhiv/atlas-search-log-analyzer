"""
Index catalog loader.
=====================

Loads a CSV dump of `db.collection.getIndexes()`-style data (as produced by
Atlas's "Indexes" export or by a custom mongosh script) and turns it into
structured data the analyzer can use to:

  * Resolve <TEXT_INDEXED_FIELD> placeholders in recommendations by reading
    the actual `text` index key fields.
  * Tag each recommendation with the existing indexes it would replace.
  * Surface drop candidates: duplicates (isDuplicate=true) and unused
    indexes (zero ops since last reset).
  * Render an inventory table per collection in the HTML report.

Expected CSV header (columns may be in any order):

    DB Name, Collection Name, Name, Type, Size (MB),
    Fragmented Size (MB), # Primary Ops, # Secondary Ops,
    Key, Options, isDuplicate

The `Key` column is parsed as a forgiving MongoDB-extended-JSON-ish doc.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IndexEntry:
    db: str
    collection: str
    name: str
    type: str                              # "regular" / "text" / "compound" / "hashed" / etc.
    size_mb: float = 0.0
    fragmented_mb: float = 0.0
    primary_ops: int = 0
    secondary_ops: int = 0
    key: dict[str, object] = field(default_factory=dict)   # {field: 1|-1|"text"|"hashed"|...}
    options_raw: str = ""
    is_duplicate: bool = False

    @property
    def namespace(self) -> str:
        return f"{self.db}.{self.collection}"

    @property
    def total_ops(self) -> int:
        return self.primary_ops + self.secondary_ops

    @property
    def is_text_index(self) -> bool:
        return self.type == "text" or any(v == "text" for v in self.key.values())

    @property
    def display_type(self) -> str:
        """A human-meaningful index type, derived from the key+options when the
        CSV's Type column is unhelpful (e.g. literally "mongod")."""
        # Look at the key first — most specific.
        vals = list(self.key.values())
        if any(v == "text" for v in vals):
            return "text"
        if any(v == "hashed" for v in vals):
            return "hashed"
        if any(v == "2dsphere" for v in vals):
            return "2dsphere"
        if any(v == "2d" for v in vals):
            return "2d"
        if "expireAfterSeconds" in (self.options_raw or ""):
            return "ttl"
        if "partialFilterExpression" in (self.options_raw or ""):
            return "partial"
        if "wildcardProjection" in (self.options_raw or "") or "$**" in (self.key or {}):
            return "wildcard"
        if len(self.key_fields) >= 2:
            return "compound"
        if len(self.key_fields) == 1:
            return "single"
        return self.type or "?"

    @property
    def key_fields(self) -> list[str]:
        """The fields the index covers, in key order, excluding MongoDB-internal
        `_fts` / `_ftsx` companion keys."""
        return [f for f in self.key.keys() if f not in ("_fts", "_ftsx")]

    @property
    def is_unused(self) -> bool:
        # The _id index always has ops=0 in some exports because it's not tracked
        # separately. Never recommend dropping it.
        if self.name == "_id_":
            return False
        return self.total_ops == 0

    @property
    def drop_candidate(self) -> str | None:
        """Return a reason string if this index is a safe drop candidate, else None."""
        if self.is_duplicate:
            return "Marked isDuplicate=true — safe to drop immediately."
        if self.is_unused:
            return f"Zero ops on primary or secondary — appears unused " \
                   f"({self.size_mb:.1f} MB reclaimable)."
        return None


@dataclass
class IndexCatalog:
    """All indexes parsed from the CSV, plus helpers for analyzer lookups."""
    entries: list[IndexEntry] = field(default_factory=list)
    parse_errors: int = 0

    # Derived caches (built once after load)
    _by_ns: dict[str, list[IndexEntry]] = field(default_factory=dict)

    def _build_caches(self) -> None:
        self._by_ns = {}
        for e in self.entries:
            self._by_ns.setdefault(e.namespace, []).append(e)

    # ------- public helpers used by the recommender ------------------------

    def for_namespace(self, ns: str) -> list[IndexEntry]:
        return self._by_ns.get(ns, [])

    def text_index_fields(self, ns: str) -> list[str]:
        """Return the field names covered by any `text` index on the namespace.

        Used to substitute <TEXT_INDEXED_FIELD> placeholders in recommendations.
        Excludes the synthetic `_fts`/`_ftsx` keys MongoDB stores in text indexes;
        returns the *real* weighted field names from `Options` if available, else
        falls back to the key fields.
        """
        out: list[str] = []
        for e in self.for_namespace(ns):
            if not e.is_text_index:
                continue
            # Try to recover weighted field names from Options (e.g. "weights: { field1: 1, field2: 1 }")
            weighted = _parse_weights(e.options_raw)
            if weighted:
                out.extend(f for f in weighted if f not in out)
            else:
                out.extend(f for f in e.key_fields if f not in out)
        return out

    def covering_indexes(self, ns: str, fields: set[str]) -> list[IndexEntry]:
        """Return indexes on `ns` whose key fields are a subset of `fields`."""
        result: list[IndexEntry] = []
        for e in self.for_namespace(ns):
            kf = set(e.key_fields)
            if kf and kf.issubset(fields):
                result.append(e)
        return result

    def drop_candidates(self) -> list[IndexEntry]:
        return [e for e in self.entries if e.drop_candidate is not None]

    def total_size_mb(self) -> float:
        return sum(e.size_mb for e in self.entries)

    def total_drop_size_mb(self) -> float:
        return sum(e.size_mb for e in self.drop_candidates())


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------

# Map (case-insensitive, whitespace-collapsed) headers → IndexEntry field name.
HEADER_ALIASES = {
    "db name":               "db",
    "database":              "db",
    "database name":         "db",
    "collection name":       "collection",
    "collection":            "collection",
    "name":                  "name",
    "index name":            "name",
    "type":                  "type",
    "size (mb)":             "size_mb",
    "size mb":               "size_mb",
    "size":                  "size_mb",
    "fragmented size (mb)":  "fragmented_mb",
    "fragmented size mb":    "fragmented_mb",
    "# primary ops":         "primary_ops",
    "primary ops":           "primary_ops",
    "# secondary ops":       "secondary_ops",
    "secondary ops":         "secondary_ops",
    "key":                   "key",
    "options":               "options_raw",
    "isduplicate":           "is_duplicate",
    "is duplicate":          "is_duplicate",
    "duplicate":             "is_duplicate",
}


def load_catalog(path: Path) -> IndexCatalog:
    """Load and parse an index-dump CSV."""
    catalog = IndexCatalog()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return catalog

        # Build a per-column mapping: csv_header -> attribute_name
        col_map: dict[str, str] = {}
        for h in reader.fieldnames:
            normalized = " ".join(h.lower().split())
            if normalized in HEADER_ALIASES:
                col_map[h] = HEADER_ALIASES[normalized]

        for row in reader:
            try:
                entry = _row_to_entry(row, col_map)
                if entry is not None:
                    catalog.entries.append(entry)
            except Exception:
                catalog.parse_errors += 1

    catalog._build_caches()
    return catalog


def _row_to_entry(row: dict[str, str], col_map: dict[str, str]) -> IndexEntry | None:
    data: dict[str, object] = {}
    for csv_key, attr in col_map.items():
        raw = (row.get(csv_key) or "").strip()
        if attr == "key":
            data["key"] = _parse_key_doc(raw)
        elif attr == "size_mb" or attr == "fragmented_mb":
            data[attr] = _to_float(raw)
        elif attr == "primary_ops" or attr == "secondary_ops":
            data[attr] = _to_int(raw)
        elif attr == "is_duplicate":
            data[attr] = _to_bool(raw)
        else:
            data[attr] = raw

    if not data.get("db") or not data.get("collection"):
        return None

    return IndexEntry(
        db=str(data.get("db", "")),
        collection=str(data.get("collection", "")),
        name=str(data.get("name", "")),
        type=str(data.get("type", "")),
        size_mb=float(data.get("size_mb", 0.0)),
        fragmented_mb=float(data.get("fragmented_mb", 0.0)),
        primary_ops=int(data.get("primary_ops", 0)),
        secondary_ops=int(data.get("secondary_ops", 0)),
        key=data.get("key") or {},  # type: ignore[arg-type]
        options_raw=str(data.get("options_raw", "")),
        is_duplicate=bool(data.get("is_duplicate", False)),
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _to_float(raw: str) -> float:
    if not raw:
        return 0.0
    raw = raw.replace(",", "").strip()
    try:
        return float(raw)
    except ValueError:
        return 0.0


def _to_int(raw: str) -> int:
    if not raw:
        return 0
    raw = raw.replace(",", "").strip()
    try:
        return int(float(raw))
    except ValueError:
        return 0


def _to_bool(raw: str) -> bool:
    return raw.strip().lower() in ("true", "1", "yes", "y", "t")


# MongoDB key docs use unquoted keys and may contain quoted string values
# (e.g. `{ _fts: "text", _ftsx: 1 }`). Build a small parser.
_KEY_TOKEN_RE = re.compile(
    r'''
    \s*
    (?P<key>[A-Za-z_$][\w$.]*|"[^"]*"|'[^']*')   # field name (bare or quoted)
    \s*:\s*
    (?P<val>
        -?\d+(?:\.\d+)?       |   # number (sort dir 1/-1 or weight)
        "[^"]*"               |   # double-quoted string
        '[^']*'               |   # single-quoted string
        \w+                       # bare token like "text" / "hashed" / "2dsphere"
    )
    \s*,?
    ''',
    re.VERBOSE,
)


def _parse_key_doc(raw: str) -> dict[str, object]:
    """Parse a MongoDB-style key document like `{ field: 1, _fts: "text" }`.

    Returns {} on any error — we never want a malformed row to abort the load.
    """
    if not raw:
        return {}
    # Strip surrounding braces; tolerate `{}`-less variants too
    s = raw.strip()
    if s.startswith("{"):
        s = s[1:]
    if s.endswith("}"):
        s = s[:-1]

    out: dict[str, object] = {}
    for m in _KEY_TOKEN_RE.finditer(s):
        k = m.group("key")
        v = m.group("val")

        # Strip quotes from key
        if (k.startswith('"') and k.endswith('"')) or (k.startswith("'") and k.endswith("'")):
            k = k[1:-1]

        # Parse value: int/float, quoted string, or bare keyword
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            out[k] = v[1:-1]
        else:
            try:
                if "." in v:
                    out[k] = float(v)
                else:
                    out[k] = int(v)
            except ValueError:
                out[k] = v       # e.g. "text", "hashed", "2dsphere"
    return out


# Find `weights: { fieldA: 1, fieldB: 2 }` or `"weights":{...}` inside the
# Options blob (text indexes have weighted fields; we want the field names
# regardless of weight). Supports both unquoted-key MongoDB-doc form and
# strict JSON form.
_WEIGHTS_RE = re.compile(r'"?weights"?\s*:\s*\{([^}]*)\}', re.IGNORECASE)


def _parse_weights(options_raw: str) -> list[str]:
    if not options_raw:
        return []
    m = _WEIGHTS_RE.search(options_raw)
    if not m:
        return []
    fields: list[str] = []
    for km in _KEY_TOKEN_RE.finditer(m.group(1)):
        f = km.group("key")
        if (f.startswith('"') and f.endswith('"')) or (f.startswith("'") and f.endswith("'")):
            f = f[1:-1]
        if f and f not in fields:
            fields.append(f)
    return fields
