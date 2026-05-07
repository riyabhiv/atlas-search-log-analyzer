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

# Full file
python3 main.py /path/to/mongod.log --out report.html

# Focused on one database, redacted for sharing
python3 main.py /path/to/mongod.log --ns "MyApp.*" --redact

# Compressed logs work directly
python3 main.py /path/to/mongod.log.gz
```

### CLI options

| Flag | Description |
|---|---|
| `log` | Path to a MongoDB structured JSON log (`.log` or `.gz`) — required |
| `--out PATH` | Output HTML report path (default: `atlas_search_report.html`) |
| `--min-duration MS` | Ignore slow-query events faster than this many ms |
| `--sample N` | Stop after N inspected slow-query events (smoke-test mode) |
| `--ns GLOB` | Limit to a namespace, supports glob (e.g. `"MyDB.*"`) |
| `--redact` | Replace string values with `xxx` and digits with `9` (production-safe sharing) |

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
7. **Migration Task Checklist** — auto-generated to-do list grouped by category and namespace, with `queryHash` references

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
