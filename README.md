# wp-crossfire

[![shellcheck](https://github.com/thereisnotime/wp-crossfire/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/thereisnotime/wp-crossfire/actions/workflows/shellcheck.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/shell-bash%204.0+-green.svg)](https://www.gnu.org/software/bash/)
[![CVE source](https://img.shields.io/badge/CVE_source-NVD-red.svg)](https://nvd.nist.gov)
[![WPScan](https://img.shields.io/badge/enrichment-WPScan-orange.svg)](https://wpscan.com/api)
[![GitHub last commit](https://img.shields.io/github/last-commit/thereisnotime/wp-crossfire)](https://github.com/thereisnotime/wp-crossfire/commits/main)
[![GitHub repo size](https://img.shields.io/github/repo-size/thereisnotime/wp-crossfire)](https://github.com/thereisnotime/wp-crossfire)

Cross-reference WordPress installs against vulnerability feeds. Built for managing large numbers of sites — dump inventory via WP-CLI, fetch CVEs from NVD, get a per-site vulnerability report.

## Quick start

```bash
# 1. Dump a site inventory (runs on the target, nothing to install)
ssh user@mysite.com 'bash -s' < wp-dump.sh > dumps/mysite.json

# 2. Cross-match against CVEs
./wp-vulns.sh --sites dumps/
```

That's it. On first run, the full 5-year CVE history is fetched from NVD and cached locally. Subsequent runs refresh only the last 30 days and merge into the existing DB, so history is never lost.

## Tested with

| WordPress Version | Status | Plugins dumped | Notes |
|-------------------|--------|----------------|-------|
| 5.9 | ✅ | 16 | Some plugins require WP 6.x+ and won't install |
| 6.0 | ✅ | 17 | Some plugins require WP 6.4+ and won't install |
| 6.4 | ✅ | 20 | |
| 6.6 | ✅ | 24 | Plugins requiring WP 6.7+ won't install |
| latest (6.9) | ✅ | 31 | Full plugin set installs cleanly |

## Requirements

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| bash | 4.0 | |
| curl | 7.x | |
| jq | 1.6 | |
| wp-cli | 2.0 | Target sites only |
| fzf | 0.30 | Optional, for interactive browsing |

## How it works

1. **Collect** — run `wp-dump.sh` on each site (SSH-pipeable, no installation required)
2. **Fetch** — pull recent WordPress/plugin/theme CVEs from NVD
3. **Match** — cross-reference installed versions against CVE ranges, get a report

## Usage

### 1. Collect site inventory

```bash
# Single site
ssh user@site1.com 'bash -s' < wp-dump.sh > dumps/site1.json

# Batch across many hosts (10 in parallel)
while read host; do
  ssh -o StrictHostKeyChecking=no "$host" 'bash -s' < wp-dump.sh > "dumps/${host}.json" &
  (( $(jobs -r | wc -l) >= 10 )) && wait -n
done < hosts.txt
wait

# Local WP install
./wp-dump.sh --path /var/www/html --site mysite.com > dumps/mysite.json
```

Dump format:
```json
{
  "site": "https://example.com",
  "label": "example.com",
  "wp_version": "6.4.2",
  "dumped_at": "2026-04-29T10:00:00Z",
  "plugins": [
    {"name": "woocommerce", "version": "8.1.0", "status": "active"}
  ],
  "themes": [
    {"name": "storefront", "version": "4.4.2", "status": "active"}
  ]
}
```

### 2. Run the report

```bash
# Full report across all dumps (fetches CVEs if DB is missing or stale)
./wp-vulns.sh --sites dumps/

# Filter to a specific plugin across all sites
./wp-vulns.sh --sites dumps/ --grep woocommerce

# Interactive fzf browser — filter by site/plugin/CVE/severity as you type
./wp-vulns.sh --sites dumps/ --fzf

# Combine: fzf filtered to elementor hits only
./wp-vulns.sh --sites dumps/ --fzf --grep elementor

# Force re-fetch CVEs (default: reuses cached DB if < 30 days old)
./wp-vulns.sh --fetch --sites dumps/

# Change CVE lookback window
./wp-vulns.sh --days 90 --sites dumps/
```

Sample output:

```
═══════════════════════════════════════════════════════
mysite.com  WP 6.4.2  (20 plugins · 3 themes)
═══════════════════════════════════════════════════════
  [CRITICAL/9.8] CVE-2024-1234  (woocommerce 8.1.0)
  WooCommerce is vulnerable to SQL Injection via the 'order_by' parameter...

  [HIGH/8.8] CVE-2024-5678  (elementor 3.18.0)
  Elementor Page Builder is vulnerable to Stored XSS via the url parameter...

  [MEDIUM/5.3] CVE-2024-9012  (wordpress 6.4.2)
  WordPress core is vulnerable to path traversal in the Filesystem API...

  Site total: 3 CVE(s) — CRITICAL:1 HIGH:1 MEDIUM:1

═══════════════════════════════════════════════════════
SUMMARY
═══════════════════════════════════════════════════════
  mysite.com        CRIT:1 HIGH:1 MED:1 TOTAL:3
  staging.mysite    CRIT:0 HIGH:2 MED:4 TOTAL:6

[*] Report saved to wp-report-20260430-120802.txt
```

### 3. Other options

```bash
# Simple slug list instead of dumps
./wp-vulns.sh --match plugins.txt   # one slug per line, or slug:version

# WPScan enrichment
WPSCAN_TOKEN=yourtoken ./wp-vulns.sh --sites dumps/

# Custom DB and report paths
./wp-vulns.sh --db /tmp/vulns.json --output /tmp/report.txt --sites dumps/
```

## Matching logic

Vulnerabilities are matched in two layers:

1. **CPE (structured)** — when NVD has CPE data for a CVE, the plugin slug is matched against the CPE `product` field and the installed version is checked against the explicit version range (`versionStartIncluding`, `versionEndExcluding`, etc.)

2. **Description fallback** — for CVEs without CPE data (common for recently published entries), a case-insensitive substring match is done against the description. No version filtering is applied; these are flagged conservatively.

WordPress core is matched only against CVEs where both CPE `vendor` and `product` are `wordpress`, avoiding false positives from plugin CVEs.

## Data sources

| Source | Auth | Notes |
|--------|------|-------|
| [NVD](https://nvd.nist.gov) | None | Primary source, free, bulk query |
| [WPScan](https://wpscan.com/api) | Token (free tier) | WordPress-specific, more precise version ranges |

NVD has enrichment lag — newly published CVEs often lack CPE data for weeks. WPScan fills that gap for WordPress specifically.

## Test environment

A Podman Compose setup under `test/` spins up five WordPress versions with a shared MariaDB, installs WP-CLI and a representative plugin set, then exports dumps ready for cross-matching.

```bash
cd test/

# Start all containers
podman compose up -d

# Install WP core + ~30 plugins in each container (actual count varies by WP version)
./setup.sh

# Export inventory from every running container → test/dumps/*.json
./dump-all.sh

# Run the cross-match against the test dumps
../wp-vulns.sh --sites dumps/
```

Versions included: **5.9 · 6.0 · 6.4 · 6.6 · latest**

Ports: `8059 8060 8064 8066 8080` — each instance is accessible via browser too.

Override the default plugin set:
```bash
PLUGINS="woocommerce akismet wpforms-lite" ./setup.sh
```

Dump a specific container only:
```bash
./dump-all.sh wp64 wplatest
```

## CVE database caching

| Run | Behaviour |
|-----|-----------|
| First run (no DB) | Fetches full 5-year history from NVD, paginating through results |
| DB exists, < 30 days old | Uses cached DB as-is |
| DB exists, ≥ 30 days old | Fetches last 30 days, merges into existing DB (no history lost) |
| `--fetch` | Forces a refresh of the last `--days` window and merges |
| `--fetch --days 1825` | Full re-fetch of 5-year history |

NVD paginates at 2000 results per request. The script handles this automatically with a short sleep between pages to stay within the rate limit.

## Output

- `wp-vulndb.json` — cached CVE database (auto-refreshed when stale)
- `wp-report-TIMESTAMP.txt` — full report, saved alongside console output

## Known limitations

- **NVD enrichment lag** — newly published CVEs often lack CPE data for days or weeks after disclosure. During that window, matches fall back to description substring search with no version filtering, so hits are conservative (may include patched versions).
- **Description fallback is noisy** — a CVE mentioning "woocommerce" in its description will match any site running WooCommerce, regardless of version. These are clearly marked in the report.
- **No CVSS v4 yet** — NVD is still rolling out CVSS v4 scores; the script uses CVSS v3.1 where available, falling back to v2.
- **Slug matching is approximate** — CPE `product` fields are not always identical to WordPress.org slugs. Uncommon plugins may be missed or produce false positives.
- **Inactive plugins are included** — the dump captures all installed plugins regardless of active status. A deactivated plugin is still a risk if it's on disk.
