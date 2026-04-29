# wp-crossfire

Cross-reference WordPress installs against vulnerability feeds. Built for managing large numbers of sites — dump inventory via WP-CLI, fetch CVEs from NVD, get a per-site vulnerability report.

## How it works

1. **Collect** — run `wp-dump.sh` on each site (SSH-pipeable, no installation required)
2. **Fetch** — pull recent WordPress/plugin/theme CVEs from NVD
3. **Match** — cross-reference installed versions against CVE ranges, get a report

## Requirements

- `bash`, `curl`, `jq`
- `wp-cli` on the target sites (already present, nothing to install)
- `fzf` (optional, for interactive browsing)
- `WPSCAN_TOKEN` env var (optional, for WPScan enrichment — free at [wpscan.com/register](https://wpscan.com/register))

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

## Output

- `wp-vulndb.json` — cached CVE database (auto-refreshed when stale)
- `wp-report-TIMESTAMP.txt` — full report, saved alongside console output
