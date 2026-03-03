# PatchThisApp March Update — Design Document

**Date:** 2026-03-03
**Branch:** MarchUpdate
**Approach:** Big Bang — parallel improvements across Python, Actions, and Web

## Constraints

- Must remain a static GitHub Pages site (no backend API, no alerting)
- Visual design must align with RogoLabs family: cve.icu, cnascorecard.org, rogolabs.org
- Keep Google Analytics (G-9V606CWMWX)

---

## 1. Python Code Improvements (`patchthisapp.py`)

### Bug Fixes
- **Fix CPE parsing**: Extract Vendor and Product from CPE strings (`cpe:2.3:a:vendor:product:...`) so the `Vendor` and `Affected Products` columns actually exist in the output CSV
- **Fix `scripts/column_summary.py`**: Align with actual output columns after CPE fix

### Enhancements
- Add CLI flags via `argparse`:
  - `--epss-threshold` (default 0.95)
  - `--output-dir` (default current behavior)
  - `--verbose` for debug output
  - `--dry-run` to report what would be produced without writing files
- Replace bare prints with proper `logging` module usage
- Pin `pandas` version in `requirements.txt` (e.g., `pandas>=2.0,<3.0`)
- Add input validation for loaded data (check expected columns exist before merge)

### What Stays
- Single file structure (270 lines doesn't justify multi-module)
- Core data flow and merge logic
- Output format (CSV, same columns plus Vendor/Product)

---

## 2. GitHub Actions Improvements (`patchthis.yml`)

### Resilience
- Add retry logic for **all** data downloads (currently only EPSS has retries)
- Replace `touch nvd.jsonl` fallback with proper error handling — use cached data from previous successful run instead of empty file
- Add validation step after `patchthisapp.py`: check that `data.csv` has >0 rows and expected columns

### Quality Gates
- Add `ruff` linting step for Python code
- Add smoke test step: `python patchthisapp.py --dry-run` on PR builds

### Workflow Improvements
- Add `workflow_dispatch` trigger for manual runs from GitHub UI
- Add job summary step reporting: CVE count, data freshness, any warnings
- Cache NVD data between runs using `actions/cache`

### Dependabot
- Add `.github/dependabot.yml` to automatically:
  - Monitor GitHub Actions for version updates (weekly)
  - Monitor pip dependencies for security and version updates (weekly)
  - Auto-create PRs when updates are available

### What Stays
- 6-hour cron schedule
- `EndBug/add-and-commit@v9` for auto-commits
- GitHub Pages deployment from `web/`

---

## 3. Web — Single Page App + Visual Refresh

### Architecture
- Consolidate `index.html`, `dashboard.html`, and `viewer.html` into a single `index.html` SPA
- Smooth scroll navigation between sections: Hero, Dashboard, Data Explorer
- Vanilla HTML/CSS/JS with Chart.js and PapaParse (no frameworks added)

### SPA Sections
1. **Hero/Landing** — streamlined intro with CTA buttons that scroll to dashboard/explorer
2. **Dashboard** — stats cards + Chart.js visualizations (same 6 charts, improved)
3. **Data Explorer** — full sortable/filterable table with all CVE data
4. **Footer** — sources, GitHub link, RogoLabs attribution

### Visual Refresh (RogoLabs Family Aligned)
- Keep the existing blue palette (`#2196f3` primary) — shared RogoLabs brand identity
- Refine design system: tighten spacing, improve card consistency, better visual hierarchy
- Light/dark mode toggle using existing `--dark` color tokens, persisted in `localStorage`
- Keep Inter font, improve typographic scale for data-dense views
- Professional, card-based, blue accent, clean white/dark surfaces

### Functional Improvements
- **Pagination** for data table (configurable rows per page)
- **Improved search** — filter across all columns, column-specific filters
- **Error states** — graceful handling if CSV fails to load, with retry button
- **Loading states** — skeleton screens while data loads
- **Keyboard navigation** — proper focus management in data table
- **ARIA labels** — screen reader support for tables, charts, navigation
- **Severity badges** — text + color indicators (not color-only)
- **Responsive** — mobile-first design, phone to widescreen

### Removed Files
- `web/viewer.html` (merged into `index.html`)
- `web/dashboard.html` (merged into `index.html`)
- `web/viewer/data.csv` (duplicate — single `web/data.csv` used)

### Kept
- Google Analytics tag (G-9V606CWMWX)
- `web/data.csv` as the data source

---

## Implementation Strategy

Big Bang approach — all three streams developed in parallel and shipped together:

1. **Python + Actions** can be worked on independently of the web layer
2. **Web SPA** is a rewrite, so it doesn't conflict with Python/Actions changes
3. Everything committed to the `MarchUpdate` branch for review before merging to `main`
