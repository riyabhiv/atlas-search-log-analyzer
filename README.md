# Atlas Search Log Analyzer

Parses MongoDB structured JSON logs (4.4+) and identifies query patterns that
are strong candidates for migration to **MongoDB Atlas Search**. Produces an
interactive HTML report with sortable/filterable tables, severity-ranked
opportunities, and a per-namespace migration task checklist.

Designed to handle very large logs (multi-GB) by streaming line-by-line and
aggregating by `queryHash`.

## What it detects

| Category | Atlas Search migration |
|---|---|
| Legacy `$text` search | `$search` `text` / `phrase` operator |
| Legacy text index (`IXSCAN _fts`) | Atlas Search index |
| `$regex` (especially leading-wildcard or `/i`) | `autocomplete` / `wildcard` operator |
| Multi-field `$or` over strings ("search bar" pattern) | `compound.should` |
| Collation `strength <= 2` (case-insensitive) | `lowercase` / `diacriticFolding` analyzer |
| `COLLSCAN` on string filters | Atlas Search index |
| High `keysExamined : nReturned` on string filters | Relevance-scored search |

## Usage

```bash
# Smoke test on a sample (recommended first run)
python3 main.py /path/to/mongod.log --sample 50000

# Full file with an index dump for sharper recommendations
python3 main.py /path/to/mongod.log --indexes indexes.csv --out report.html

# Focused on one database, redacted for sharing
python3 main.py /path/to/mongod.log --ns "MyApp.*" --redact

# Compressed logs work directly
python3 main.py /path/to/mongod.log.gz
```

If a file named `indexes.csv` exists in the same directory as the log,
it is auto-loaded — no `--indexes` flag needed.

### CLI options

| Flag | Description |
|---|---|
| `log` | Path to a MongoDB structured JSON log (`.log` or `.gz`) — required |
| `--out PATH` | Output HTML report path (default: `atlas_search_report.html`) |
| `--min-duration MS` | Ignore slow-query events faster than this many ms |
| `--sample N` | Stop after N inspected slow-query events (smoke-test mode) |
| `--ns GLOB` | Limit to a namespace, supports glob (e.g. `"MyDB.*"`) |
| `--redact` | Replace string values with `xxx` and digits with `9` (production-safe sharing) |
| `--indexes PATH` | CSV dump of cluster indexes. Auto-detects `indexes.csv` next to the log if omitted. |

### Index CSV format

The expected CSV header (column order is flexible, case-insensitive):

```
DB Name, Collection Name, Name, Type, Size (MB), Fragmented Size (MB),
# Primary Ops, # Secondary Ops, Key, Options, isDuplicate
```

The `Key` column is parsed as a forgiving MongoDB-style document — both
quoted-JSON (`{"field": 1}`) and unquoted-mongo-doc (`{ field: 1 }`)
forms are accepted. For `text` indexes, the analyzer recovers real
weighted field names from the `Options` column's `weights: { ... }`
block, which is used to resolve `<TEXT_INDEXED_FIELD>` placeholders in
the generated `$search` pipelines.

## Report sections

1. **Summary** — high-level counts and time window
2. **Atlas Search Opportunities** — severity-filterable, expandable rows. Each row reveals:
   - Reasons + suggested Atlas Search operator
   - **Suggested Atlas Search index definition** (copy-pasteable JSON)
   - **Replacement aggregation pipeline** beginning with `$search`
   - Caveats / analyzer-choice notes
   - Raw log sample
3. **All Query Shapes** — top 200 by total duration
4. **Top Namespaces / Categories**
5. **Operations / Plan Summaries**
6. **Error Codes**
7. **Drop Candidates** *(when an index CSV is supplied)* — indexes that are safe to drop right now: marked `isDuplicate=true`, or with zero primary and secondary ops since stats reset. Conservative policy: indexes covered by a proposed Atlas Search index are **not** in this list — they should only be dropped after the Search index is built and validated.
8. **Index Inventory** *(when an index CSV is supplied)* — full table of every index with size, ops, key, derived type (single / compound / text / ttl / 2dsphere / partial), and flags (`text` / `dup` / `unused`).
9. **Migration Task Checklist** — auto-generated to-do list grouped by category and namespace, with `queryHash` references

## Recommendation engine

For every detected opportunity the analyzer synthesizes:

1. **Atlas Search index definition** with `dynamic: false` and one explicit field
   per role (text-searchable → `string`/`lucene.standard`, equality →
   `token`/`lowercase`, autocomplete → `autocomplete`/`edgeGram`, range/sort →
   typed `date`/`number`).
2. **`$search` aggregation pipeline** that maps each part of the original query
   onto a `compound` clause:
   - `$text` / regex / `$or` text-fields → `compound.must` / `compound.should`
   - Equality (`{f: v}`, `{f: {$eq: v}}`, `{f: {$in: [...]}}`) → `compound.filter.equals`
   - Range (`$gte`/`$lte`/`$gt`/`$lt`) → `compound.filter.range`
   - Original `$sort` / `$skip` / `$limit` are preserved after `$search`.

The recommendations are heuristic starting points. The "Notes" block in each
expandable row flags caveats (analyzer language, phrase vs. text, sort by
score vs. timestamp, ObjectId equality residuals, etc.).

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## How it works

1. Stream the log file line by line (works on 4 GB+ logs).
2. Filter to `"Slow query"` events on `COMMAND` / `WRITE` / `QUERY` components.
3. Skip internal namespaces (`admin.*`, `local.*`, `config.*`).
4. Aggregate by `(queryHash, namespace)` so 150k slow queries collapse into a few hundred distinct query *shapes*.
5. Run all detectors against each shape's filter / pipeline / planSummary / collation.
6. Render an interactive HTML report.

## Privacy

Use `--redact` when sharing reports outside your team. It replaces all string
field values with `xxx`, redacts numeric values, and keeps timestamps,
field names, namespaces, plan summaries, and metrics intact for analysis.

## License

MIT
