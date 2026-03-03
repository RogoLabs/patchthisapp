# March Update Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Comprehensive overhaul of PatchThisApp — fix Python bugs, harden GitHub Actions with Dependabot, and convert the 3-page web interface into a single-page app with a visual refresh aligned to the RogoLabs family.

**Architecture:** Three parallel streams (Python, Actions, Web) developed Big Bang style on the `MarchUpdate` branch. The Python stream fixes data correctness (CPE parsing, CLI flags). The Actions stream adds resilience, quality gates, and Dependabot. The Web stream rewrites the 3 HTML files into a single SPA with light/dark mode, pagination, and accessibility. All must remain compatible with GitHub Pages static deployment.

**Tech Stack:** Python 3.13, pandas, argparse, logging | GitHub Actions, ruff, Dependabot | Vanilla HTML/CSS/JS, Chart.js 4.4, PapaParse 5.4, dayjs 1.11

---

## Stream A: Python Code Improvements

### Task 1: Add CPE Vendor/Product Parsing

**Files:**
- Modify: `patchthisapp.py:110-123` (extract_entry_data CPE section)
- Modify: `patchthisapp.py:239-267` (main output columns)

**Step 1: Add CPE parsing helper function**

Add this function before `extract_entry_data` (around line 88):

```python
def parse_cpe_fields(cpe_string: str) -> Tuple[str, str]:
    """Extract vendor and product from a CPE 2.3 string.

    CPE format: cpe:2.3:part:vendor:product:version:...
    """
    if not cpe_string:
        return ('', '')
    parts = cpe_string.split(':')
    if len(parts) >= 5:
        vendor = parts[3].replace('_', ' ').title()
        product = parts[4].replace('_', ' ').title()
        return (vendor, product)
    return ('', '')
```

**Step 2: Update extract_entry_data to use it**

In `extract_entry_data`, after the CPE list is built (line 122-123), add vendor/product extraction:

```python
        if cpe_list:
            fields['cpe'] = ';'.join(sorted(set(cpe_list)))
            # Extract vendor/product from first CPE
            vendor, product = parse_cpe_fields(cpe_list[0])
            fields['vendor'] = vendor
            fields['product'] = product
```

Also add `'vendor': ''` and `'product': ''` to the initial `fields` dict (around line 90).

**Step 3: Update output columns in main()**

In `main()` at lines 245-251, add Vendor and Product to the column lists:

```python
        columns = ['CVE', 'CVSS Score', 'cvss_vector', 'epss', 'Description', 'Published', 'Source', 'cpe', 'vendor', 'product']
        patchthisapp_df = patchthisapp_df[columns]
        patchthisapp_df = patchthisapp_df.rename(columns={
            "epss": "EPSS",
            "cvss_vector": "CVSS_Vector",
            "cpe": "CPE",
            "vendor": "Vendor",
            "product": "Affected Products"
        })
```

Do the same for the else branch (no EPSS data).

**Step 4: Verify the script runs**

Run: `python patchthisapp.py --help`
Expected: No import errors, help text displayed

**Step 5: Commit**

```bash
git add patchthisapp.py
git commit -m "feat: add CPE vendor/product parsing to output CSV"
```

---

### Task 2: Add CLI Flags (--epss-threshold, --verbose, --dry-run)

**Files:**
- Modify: `patchthisapp.py:209-218` (argparse section)
- Modify: `patchthisapp.py:69` (EPSS threshold)
- Modify: `patchthisapp.py:253-267` (output writing)

**Step 1: Add new argparse arguments**

After line 217, add:

```python
    parser.add_argument('--epss-threshold', type=float, default=0.95,
                        help='EPSS score threshold (default: 0.95)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose/debug logging')
    parser.add_argument('--dry-run', action='store_true',
                        help='Report what would be produced without writing files')
```

**Step 2: Wire up verbose logging**

After `args = parser.parse_args()`, add:

```python
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
```

**Step 3: Use epss-threshold instead of hardcoded 0.95**

In `load_epss()`, change the function signature and the threshold:

```python
def load_epss(epss_path: Path, threshold: float = 0.95) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load EPSS data and return filtered and full datasets."""
    df = load_csv(epss_path, skiprows=1)
    if df.empty:
        return df, df
    df = df.rename(columns={"cve": "CVE"})
    df_all = df.copy()
    df = df[df.epss > threshold].copy()
    df['Source'] = 'EPSS'
    return df[['CVE', 'Source']], df_all
```

Update the call in `main()`:

```python
    epss_df, epss_df_all = load_epss(args.epss, args.epss_threshold)
```

**Step 4: Implement dry-run**

Before the output writing section (around line 253), wrap the file writes:

```python
    logging.info(f"Final dataset: {len(patchthisapp_df)} CVEs")
    if args.dry_run:
        logging.info("Dry run mode — no files written")
        logging.info(f"Columns: {list(patchthisapp_df.columns)}")
        logging.info(f"Sample:\n{patchthisapp_df.head()}")
        return

    # ... existing file writing code ...
```

**Step 5: Verify**

Run: `python patchthisapp.py --dry-run --verbose --help`
Expected: Help text shows all new flags

**Step 6: Commit**

```bash
git add patchthisapp.py
git commit -m "feat: add --epss-threshold, --verbose, --dry-run CLI flags"
```

---

### Task 3: Pin Dependencies and Fix column_summary.py

**Files:**
- Modify: `requirements.txt`
- Modify: `scripts/column_summary.py`

**Step 1: Pin pandas version**

Replace contents of `requirements.txt`:

```
pandas>=2.0,<3.0
```

**Step 2: Fix column_summary.py**

Replace contents to handle columns that may or may not exist:

```python
import pandas as pd
import sys

def main():
    try:
        df = pd.read_csv('data/data.csv')
    except FileNotFoundError:
        print("Error: data/data.csv not found. Run patchthisapp.py first.")
        sys.exit(1)

    for col in ['Vendor', 'Affected Products', 'CVSS_Vector']:
        print(f'\n--- {col} ---')
        if col not in df.columns:
            print(f'Column "{col}" not found in data. Available: {list(df.columns)}')
            continue
        print('Non-empty count:', df[col].notna().sum())
        print('Unique values:', df[col].nunique())
        print('Top 10 most common:')
        print(df[col].value_counts().head(10))

if __name__ == "__main__":
    main()
```

**Step 3: Commit**

```bash
git add requirements.txt scripts/column_summary.py
git commit -m "fix: pin pandas version and fix column_summary for missing columns"
```

---

### Task 4: Remove Duplicate web/viewer/data.csv Output

**Files:**
- Modify: `patchthisapp.py:263-267` (remove viewer copy)

**Step 1: Remove the viewer copy block**

Delete lines 263-267 (the block that writes to `web/viewer/data.csv`). The SPA will only use `web/data.csv`.

**Step 2: Commit**

```bash
git add patchthisapp.py
git commit -m "chore: remove duplicate web/viewer/data.csv output"
```

---

## Stream B: GitHub Actions + Dependabot

### Task 5: Add Dependabot Configuration

**Files:**
- Create: `.github/dependabot.yml`

**Step 1: Create dependabot.yml**

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    commit-message:
      prefix: "ci"
    labels:
      - "dependencies"
      - "github-actions"

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    commit-message:
      prefix: "deps"
    labels:
      - "dependencies"
      - "python"
```

**Step 2: Commit**

```bash
git add .github/dependabot.yml
git commit -m "ci: add Dependabot for Actions and pip dependency updates"
```

---

### Task 6: Harden GitHub Actions Workflow

**Files:**
- Modify: `.github/workflows/patchthis.yml`

**Step 1: Add workflow_dispatch trigger**

Add `workflow_dispatch:` to the `on:` block:

```yaml
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:
  schedule:
    - cron: "0 */6 * * *"
```

**Step 2: Add retry logic for all downloads**

Replace the "Grab Needed Data" step with retried versions for all downloads. Wrap each download in a retry loop similar to the existing EPSS retry. Replace the `touch nvd.jsonl` fallback with:

```bash
        # Download NVD data with retry
        for i in {1..3}; do
          if wget https://nvd.handsonhacking.org/nvd.jsonl -O nvd.jsonl; then
            break
          elif [ $i -eq 3 ]; then
            echo "WARNING: Failed to download NVD data after 3 attempts"
            if [ -f nvd.jsonl ] && [ -s nvd.jsonl ]; then
              echo "Using cached NVD data"
            else
              echo "No cached NVD data available"
              exit 1
            fi
          else
            echo "Attempt $i failed, retrying..."
            sleep 5
          fi
        done
```

Apply similar retry patterns for Metasploit, Nuclei, and CISA downloads.

**Step 3: Add NVD data caching**

Add a cache step after checkout:

```yaml
    - name: Cache NVD data
      uses: actions/cache@v4
      with:
        path: nvd.jsonl
        key: nvd-data-${{ github.run_number }}
        restore-keys: |
          nvd-data-
```

**Step 4: Add validation step after processing**

After the "Run PatchThisApp" step, add:

```yaml
    - name: Validate output
      run: |
        if [ ! -f data/data.csv ]; then
          echo "ERROR: data/data.csv not generated"
          exit 1
        fi
        ROW_COUNT=$(tail -n +2 data/data.csv | wc -l)
        echo "Output contains $ROW_COUNT CVEs"
        if [ "$ROW_COUNT" -lt 1 ]; then
          echo "ERROR: Output CSV is empty"
          exit 1
        fi
        echo "### Vulnerability Data Update" >> $GITHUB_STEP_SUMMARY
        echo "- **CVEs processed:** $ROW_COUNT" >> $GITHUB_STEP_SUMMARY
        echo "- **Run time:** $(date -u)" >> $GITHUB_STEP_SUMMARY
```

**Step 5: Add ruff linting step**

Add before "Run PatchThisApp":

```yaml
    - name: Lint Python code
      run: |
        pip install ruff
        ruff check patchthisapp.py scripts/
```

**Step 6: Add dry-run smoke test on PRs**

Add after lint step:

```yaml
    - name: Smoke test (PR only)
      if: github.event_name == 'pull_request'
      run: |
        touch metasploit.txt nuclei.txt known_exploited_vulnerabilities.csv epss_scores-current.csv nvd.jsonl
        python patchthisapp.py --dry-run || true
```

**Step 7: Commit**

```bash
git add .github/workflows/patchthis.yml
git commit -m "ci: harden workflow with retries, caching, validation, linting, and manual trigger"
```

---

## Stream C: Web — Single Page App + Visual Refresh

### Task 7: Create the SPA index.html

**Files:**
- Rewrite: `web/index.html` (complete rewrite — combines index, dashboard, viewer)
- Delete after SPA is working: `web/dashboard.html`, `web/viewer.html`, `web/viewer/` directory

**Step 1: Write the SPA HTML structure**

Create `web/index.html` with these sections:
1. **Nav bar** — sticky top navigation with smooth scroll anchors (#hero, #dashboard, #explorer) plus GitHub link and dark mode toggle
2. **Hero section** — PatchThisApp title, subtitle, CTA buttons scrolling to dashboard/explorer, trust indicators
3. **Dashboard section** — stats cards (Total, High Severity, Critical, Avg CVSS) + 6 Chart.js charts
4. **Data Explorer section** — search bar, column filters, paginated sortable table with ARIA labels
5. **Sources section** — 4 intelligence source cards (CISA, Metasploit, Nuclei, EPSS)
6. **Footer** — RogoLabs attribution, copyright, GitHub link

Key implementation details:
- Google Analytics tag preserved: `G-9V606CWMWX`
- Single CSV load: `fetch('./data.csv')` with PapaParse
- Data shared between dashboard and explorer (one `allData` array)
- Libraries loaded from CDN: Chart.js 4.4, PapaParse 5.4, dayjs 1.11
- No additional frameworks

**Pagination implementation:**
```javascript
const ROWS_PER_PAGE = 50;
let currentPage = 1;

function renderPage(data, page) {
    const start = (page - 1) * ROWS_PER_PAGE;
    const end = start + ROWS_PER_PAGE;
    const pageData = data.slice(start, end);
    renderTableRows(pageData);
    renderPaginationControls(data.length, page);
}
```

**Dark mode toggle:**
```javascript
function toggleDarkMode() {
    document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme',
        document.documentElement.classList.contains('dark') ? 'dark' : 'light'
    );
}
// Restore on load
if (localStorage.getItem('theme') === 'dark') {
    document.documentElement.classList.add('dark');
}
```

**Accessibility:**
- `<table role="grid" aria-label="Vulnerability data">`
- `<th scope="col" aria-sort="ascending|descending|none">`
- Severity badges: `<span class="badge badge-critical" aria-label="Critical severity">Critical</span>`
- Dark mode toggle: `<button aria-label="Toggle dark mode">`
- Skip-to-content link

**Error handling:**
```javascript
} catch (error) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('error').style.display = 'flex';
}
// Retry button
document.getElementById('retryBtn').addEventListener('click', loadData);
```

**Step 2: Verify SPA loads locally**

Run: `cd web && python -m http.server 8000`
Open: `http://localhost:8000`
Expected: All 4 sections render, charts display, table paginates, dark mode toggles

**Step 3: Commit**

```bash
git add web/index.html
git commit -m "feat: convert web interface to single-page app with dashboard and explorer"
```

---

### Task 8: Rewrite modern.css with Dark Mode

**Files:**
- Rewrite: `web/modern.css`

**Step 1: Write the new CSS**

Key changes:
- Keep RogoLabs blue palette (`#2196f3` primary family) — this is the shared brand
- Add `html.dark` selectors that override CSS custom properties for dark mode
- Consolidate all dashboard-specific and viewer-specific styles (currently inline in those files) into `modern.css`
- Remove orphaned classes from deleted pages
- Improve responsive breakpoints
- Add pagination controls styling
- Add severity badge styles (text + color)
- Add skeleton loading animations
- Add smooth scroll behavior

Dark mode variables:
```css
html.dark {
    --background: #0f172a;
    --surface: #1e293b;
    --surface-alt: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --border: #334155;
    --border-light: #475569;
    /* Primary blue stays the same in dark mode */
    --primary: #2196f3;
    --primary-dark: #42a5f5;
}
```

Severity badge styles:
```css
.badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge-critical { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.badge-high { background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }
.badge-medium { background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
.badge-low { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }

html.dark .badge-critical { background: #450a0a; color: #fca5a5; border-color: #7f1d1d; }
html.dark .badge-high { background: #431407; color: #fdba74; border-color: #7c2d12; }
html.dark .badge-medium { background: #422006; color: #fde047; border-color: #713f12; }
html.dark .badge-low { background: #052e16; color: #86efac; border-color: #14532d; }
```

**Step 2: Verify styles apply**

Refresh `http://localhost:8000`, toggle dark mode, check responsive at 768px and 480px breakpoints.

**Step 3: Commit**

```bash
git add web/modern.css
git commit -m "feat: rewrite CSS with dark mode support and consolidated styles"
```

---

### Task 9: Clean Up Deleted Files and Update References

**Files:**
- Delete: `web/dashboard.html`
- Delete: `web/viewer.html`
- Delete: `web/viewer/` directory
- Modify: `README.md` (update project structure, fix inaccuracies)
- Modify: `.github/workflows/patchthis.yml` (update commit paths if needed)

**Step 1: Delete old web files**

```bash
rm web/dashboard.html web/viewer.html
rm -rf web/viewer/
```

**Step 2: Update README.md**

- Update project structure to show single `web/index.html` instead of 3 pages
- Remove references to `--output-dir` flag (it's `--output`)
- Remove "JSON API" section (doesn't exist)
- Fix the documented columns to match actual output
- Update copyright year to 2026
- Remove duplicate "Data Processing Engine" section

**Step 3: Update patchthis.yml commit paths**

The commit step already uses `add: 'data/ web/'` which will work with the new structure. No changes needed.

**Step 4: Commit**

```bash
git rm web/dashboard.html web/viewer.html
git rm -rf web/viewer/
git add README.md
git commit -m "chore: remove old multi-page files and update README"
```

---

### Task 10: Final Integration Verification

**Step 1: Run the full pipeline locally**

```bash
python scripts/local_data.py
python patchthisapp.py --verbose
```

Expected: No errors, `data/data.csv` and `web/data.csv` generated with Vendor and Affected Products columns.

**Step 2: Verify the web SPA**

```bash
cd web && python -m http.server 8000
```

Check:
- [ ] Hero section renders with CTA buttons
- [ ] Dashboard stats cards show correct numbers
- [ ] All 6 charts render with data
- [ ] Data explorer table loads and paginates
- [ ] Search filters work across all columns
- [ ] Column sorting works (click headers)
- [ ] Dark mode toggle works and persists on refresh
- [ ] Mobile responsive at 768px and 480px
- [ ] Download CSV button works
- [ ] Smooth scroll navigation works
- [ ] No console errors

**Step 3: Lint check**

```bash
pip install ruff
ruff check patchthisapp.py scripts/
```

Fix any issues found.

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final integration fixes for March Update"
```

---

## Task Execution Order

These tasks can be parallelized in two groups:

**Group 1 (Python + Actions) — Tasks 1-6:**
Tasks 1 → 2 → 3 → 4 (sequential, each builds on prior)
Task 5 (independent — Dependabot config)
Task 6 (independent — Actions hardening)

**Group 2 (Web) — Tasks 7-8:**
Task 7 → 8 (sequential — SPA HTML then CSS)

**Group 3 (Cleanup) — Tasks 9-10:**
Task 9 (depends on Group 1 + 2 complete)
Task 10 (final, depends on everything)
