#!/usr/bin/env bash
# wp-vulns.sh — fetch WordPress CVEs and cross-match against site inventory dumps
#
# Sources:
#   NVD (https://nvd.nist.gov) — free, no auth needed
#   WPScan (https://wpscan.com/api) — optional, set WPSCAN_TOKEN env var
#
# Workflow:
#   1. Collect dumps:  ssh user@host 'bash -s' < wp-dump.sh > dumps/site1.json
#   2. Fetch CVEs:     ./wp-vulns.sh --fetch
#   3. Cross-match:    ./wp-vulns.sh --sites dumps/
#   Or combined:       ./wp-vulns.sh --sites dumps/
#
# Options:
#   --days  N        CVE lookback window (default: 30)
#   --db    FILE     cached vuln DB to use/write (default: wp-vulndb.json)
#   --fetch          force re-fetch even if DB exists
#   --sites DIR      directory of wp-dump.sh JSON files to match against
#   --match FILE     simple slug list (one per line, slug or slug:version)
#   --output FILE    report output file (default: wp-report-TIMESTAMP.txt)
#   --grep  PATTERN  search the vuln DB (grep-style; pipe through fzf if available)
#   --fzf            interactive browse of the full vuln DB via fzf
#   WPSCAN_TOKEN=x   enrich with WPScan plugin-level data

set -euo pipefail

# ── prerequisite checks ───────────────────────────────────────────────────────
require_tool() {
  local name="$1" min="$2" actual="$3"
  if [[ -z "$actual" ]]; then
    echo "Error: $name is required but not found (need >= $min)" >&2; exit 1
  fi
  if ! printf '%s\n%s\n' "$min" "$actual" | sort -V -C 2>/dev/null; then
    echo "Error: $name $actual is too old (need >= $min)" >&2; exit 1
  fi
}

if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "Error: bash ${BASH_VERSION} is too old (need >= 4.0)" >&2; exit 1
fi
require_tool curl 7.0 "$(curl --version 2>/dev/null | head -1 | awk '{print $2}')"
require_tool jq  1.6 "$(jq --version 2>/dev/null | sed 's/jq-//')"

DAYS=30
DB_FILE="wp-vulndb.json"
FORCE_FETCH=0
SITES_DIR=""
MATCH_FILE=""
GREP_PATTERN=""
FZF_MODE=0
OUTPUT="wp-report-$(date +%Y%m%d-%H%M%S).txt"
WPSCAN_TOKEN="${WPSCAN_TOKEN:-}"
NVD_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
# WPSCAN_BASE reserved for future WPScan enrichment
# shellcheck disable=SC2034
WPSCAN_BASE="https://wpscan.com/api/v3"

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

usage() { grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --days)   DAYS="$2";       shift 2 ;;
    --db)     DB_FILE="$2";    shift 2 ;;
    --fetch)  FORCE_FETCH=1;   shift   ;;
    --sites)  SITES_DIR="$2";  shift 2 ;;
    --match)  MATCH_FILE="$2";    shift 2 ;;
    --output) OUTPUT="$2";        shift 2 ;;
    --grep)   GREP_PATTERN="$2";  shift 2 ;;
    --fzf)    FZF_MODE=1;         shift   ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── version comparison (uses sort -V from GNU coreutils) ────────────────────
ver_lte() {
  # true if $1 <= $2
  [ "$1" = "$2" ] || [ "$1" = "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" ]
}

# true if installed_ver is within the CVE's affected range
version_is_affected() {
  local installed="$1" vsi="$2" vse="$3" vei="$4" vee="$5"
  # No version bounds at all → wildcard match (assume affected)
  [[ -z "$vsi$vse$vei$vee" ]] && return 0
  # Lower bound — start including
  [[ -n "$vsi" ]] && ! ver_lte "$vsi" "$installed" && return 1
  # Lower bound — start excluding (installed must be strictly greater)
  if [[ -n "$vse" ]]; then
    ver_lte "$installed" "$vse" && return 1
  fi
  # Upper bound — end including
  [[ -n "$vei" ]] && ! ver_lte "$installed" "$vei" && return 1
  # Upper bound — end excluding (installed must be strictly less)
  if [[ -n "$vee" ]]; then
    ver_lte "$vee" "$installed" && return 1
  fi
  return 0
}

# ── NVD fetch ────────────────────────────────────────────────────────────────
fetch_nvd() {
  local start_date end_date
  start_date=$(date -u -d "-${DAYS} days" +%Y-%m-%dT00:00:00.000)
  end_date=$(date -u +%Y-%m-%dT23:59:59.999)
  local url="${NVD_BASE}?keywordSearch=wordpress&pubStartDate=${start_date}&pubEndDate=${end_date}&resultsPerPage=2000"
  local raw="${TMPDIR_WORK}/nvd_raw.json"
  local attempt=1 max=4 delay=10 http_code

  echo "[*] Fetching WordPress CVEs from NVD (last ${DAYS} days)..."
  while [[ $attempt -le $max ]]; do
    http_code=$(curl -s -o "$raw" -w "%{http_code}" --max-time 45 "$url")
    if [[ "$http_code" == "200" ]]; then break; fi
    echo "  NVD returned $http_code, retrying in ${delay}s (attempt $attempt/$max)..."
    sleep "$delay"; delay=$((delay * 2)); attempt=$((attempt + 1))
  done
  [[ "$http_code" != "200" ]] && { echo "Error: NVD fetch failed"; exit 1; }

  local count
  count=$(jq '.vulnerabilities | length' "$raw")
  echo "[*] Got ${count} CVEs from NVD"

  # Normalize: flat structure with structured CPE version ranges
  echo "[*] Normalizing..."
  jq '[
    .vulnerabilities[]
    | .cve as $cve
    | {
        id:          $cve.id,
        published:   $cve.published,
        severity: (
          $cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
          $cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
          $cve.metrics.cvssMetricV2[0].baseSeverity //
          "UNKNOWN"
        ),
        score: (
          $cve.metrics.cvssMetricV31[0].cvssData.baseScore //
          $cve.metrics.cvssMetricV30[0].cvssData.baseScore //
          $cve.metrics.cvssMetricV2[0].cvssData.baseScore //
          null
        ),
        description: (
          ($cve.descriptions // []) | map(select(.lang=="en")) | .[0].value // ""
        ),
        references: [ ($cve.references // []).[].url ],
        affected: [
          ($cve.configurations // [])[]?.nodes[]?.cpeMatch[]?
          | select(.vulnerable == true)
          | {
              product:   (.criteria | split(":")[4]),
              vendor:    (.criteria | split(":")[3]),
              vsi:       (.versionStartIncluding // ""),
              vse:       (.versionStartExcluding // ""),
              vei:       (.versionEndIncluding   // ""),
              vee:       (.versionEndExcluding   // ""),
              criteria:  .criteria
            }
        ]
      }
  ] | sort_by(.published) | reverse' "$raw" > "$DB_FILE"

  echo "[*] Saved vuln DB to $DB_FILE"
}

# Fetch if DB is missing, stale (older than $DAYS days), or --fetch forced
if [[ "$FORCE_FETCH" -eq 1 ]] || [[ ! -f "$DB_FILE" ]]; then
  fetch_nvd
else
  db_age_days=$(( ( $(date +%s) - $(date +%s -r "$DB_FILE") ) / 86400 ))
  if [[ "$db_age_days" -ge "$DAYS" ]]; then
    echo "[*] DB is ${db_age_days}d old, re-fetching..."
    fetch_nvd
  else
    echo "[*] Using cached DB: $DB_FILE (${db_age_days}d old)"
  fi
fi

total=$(jq 'length' "$DB_FILE")
echo ""
echo "Vuln DB: $total CVEs"
jq -r 'group_by(.severity) | .[] | "  \(.[0].severity): \(length)"' "$DB_FILE"

# ── helper: match one component (slug + version) against vuln DB ─────────────
# Writes matching CVE IDs + details to stdout as JSON array
match_component() {
  local slug="$1" version="$2"
  local hits_file="${TMPDIR_WORK}/hits_${slug//\//_}.json"
  # Normalize slug for comparison: lowercase, hyphens→underscores
  local slug_norm
  slug_norm=$(echo "$slug" | tr '[:upper:]' '[:lower:]' | tr '-' '_')

  if [[ "$slug_norm" == "wordpress" || "$slug_norm" == "wordpress_core" ]]; then
    # Core: only CVEs whose CPE vendor=wordpress AND product=wordpress
    jq '[.[] | select(.affected | length > 0) | select(
          any(.affected[]; .vendor == "wordpress" and .product == "wordpress")
        )]' "$DB_FILE" > "$hits_file" 2>/dev/null || echo '[]' > "$hits_file"
  else
    # Plugins/themes: prefer CPE product match; fall back to description only
    # when a CVE has NO CPE data at all (older/unstructured entries)
    jq --arg s "$slug_norm" '[
      .[] | select(
        (
          (.affected | length > 0) and
          any(.affected[]; .product | gsub("-";"_") | ascii_downcase | contains($s))
        ) or (
          (.affected | length == 0) and
          (.description | ascii_downcase | contains($s))
        )
      )
    ]' "$DB_FILE" > "$hits_file" 2>/dev/null || echo '[]' > "$hits_file"
  fi

  local candidate_count
  candidate_count=$(jq 'length' "$hits_file")
  [[ "$candidate_count" -eq 0 ]] && { echo '[]'; return; }

  # Step 2: if we have an installed version, filter by CPE version ranges
  if [[ -z "$version" || "$version" == "any" ]]; then
    cat "$hits_file"
    return
  fi

  local confirmed_file="${TMPDIR_WORK}/confirmed_${slug//\//_}.json"
  echo '[]' > "$confirmed_file"

  while IFS= read -r cve_json; do
    local affected_count
    affected_count=$(echo "$cve_json" | jq '.affected | length')

    if [[ "$affected_count" -eq 0 ]]; then
      # No CPE data — can't version-check, include conservatively
      jq '. + [$entry]' --argjson entry "$cve_json" "$confirmed_file" > "${confirmed_file}.tmp" \
        && mv "${confirmed_file}.tmp" "$confirmed_file"
      continue
    fi

    # Check each affected CPE entry for this slug
    local matched=0
    while IFS= read -r cpe_json; do
      local product vsi vse vei vee
      product=$(echo "$cpe_json" | jq -r '.product')
      vsi=$(echo "$cpe_json" | jq -r '.vsi')
      vse=$(echo "$cpe_json" | jq -r '.vse')
      vei=$(echo "$cpe_json" | jq -r '.vei')
      vee=$(echo "$cpe_json" | jq -r '.vee')

      # Only check version range if this CPE entry is for our slug
      if echo "$product" | grep -qi "$slug" 2>/dev/null || \
         echo "$slug" | grep -qi "$product" 2>/dev/null; then
        if version_is_affected "$version" "$vsi" "$vse" "$vei" "$vee"; then
          matched=1; break
        fi
      fi
    done < <(echo "$cve_json" | jq -c '.affected[]')

    if [[ "$matched" -eq 1 ]]; then
      jq '. + [$entry]' --argjson entry "$cve_json" "$confirmed_file" > "${confirmed_file}.tmp" \
        && mv "${confirmed_file}.tmp" "$confirmed_file"
    fi
  done < <(jq -c '.[]' "$hits_file")

  cat "$confirmed_file"
}

# ── format a CVE hit for the report ──────────────────────────────────────────
format_hit() {
  local slug="$1" version="$2" hits_json="$3"
  echo "$hits_json" | jq -r --arg slug "$slug" --arg ver "$version" '
    .[] |
    "  [\(.severity)/\(.score // "N/A")] \(.id)  (\($slug) \($ver))\n" +
    "  \(.description | .[0:160])\n"
  '
}

# ── --sites mode: process directory of wp-dump.sh JSON files ─────────────────
if [[ -n "$SITES_DIR" ]]; then
  [[ -d "$SITES_DIR" ]] || { echo "Error: $SITES_DIR is not a directory"; exit 1; }
  mapfile -t dump_files < <(find "$SITES_DIR" -maxdepth 1 -name '*.json' | sort)
  [[ ${#dump_files[@]} -eq 0 ]] && { echo "No *.json dump files found in $SITES_DIR"; exit 1; }

  # fzf mode: collect all hits as flat TSV, then open in fzf
  if [[ "$FZF_MODE" -eq 1 ]]; then
    command -v fzf &>/dev/null || { echo "Error: fzf not found (apt/brew install fzf)"; exit 1; }
    FZF_TMP="${TMPDIR_WORK}/fzf_hits.tsv"
    : > "$FZF_TMP"
    echo "[*] Collecting vulnerability hits across ${#dump_files[@]} sites..."
    for dump_file in "${dump_files[@]}"; do
      label=$(jq -r '.label // .site // "unknown"' "$dump_file")
      wp_ver=$(jq -r '.wp_version // "unknown"' "$dump_file")
      # core
      if [[ "$wp_ver" != "unknown" ]]; then
        hits=$(match_component "wordpress" "$wp_ver")
        jq -r --arg site "$label" --arg slug "wordpress-core" --arg ver "$wp_ver" \
          '.[] | [$site, "CORE", $slug, $ver, .severity, (.score|tostring), .id, (.description|.[0:200])] | @tsv' \
          <<< "$hits" >> "$FZF_TMP" 2>/dev/null || true
      fi
      # plugins
      while IFS= read -r comp; do
        slug=$(jq -r '.name'    <<< "$comp")
        ver=$(jq -r '.version'  <<< "$comp")
        kind="PLUGIN/$(jq -r '.status' <<< "$comp")"
        # skip if --grep set and slug doesn't match
        [[ -n "$GREP_PATTERN" ]] && ! echo "$slug" | grep -qi "$GREP_PATTERN" && continue
        hits=$(match_component "$slug" "$ver")
        jq -r --arg site "$label" --arg kind "$kind" --arg slug "$slug" --arg ver "$ver" \
          '.[] | [$site, $kind, $slug, $ver, .severity, (.score|tostring), .id, (.description|.[0:200])] | @tsv' \
          <<< "$hits" >> "$FZF_TMP" 2>/dev/null || true
      done < <(jq -c '.plugins[]' "$dump_file" 2>/dev/null || true)
      # themes
      while IFS= read -r comp; do
        slug=$(jq -r '.name'    <<< "$comp")
        ver=$(jq -r '.version'  <<< "$comp")
        kind="THEME/$(jq -r '.status' <<< "$comp")"
        [[ -n "$GREP_PATTERN" ]] && ! echo "$slug" | grep -qi "$GREP_PATTERN" && continue
        hits=$(match_component "$slug" "$ver")
        jq -r --arg site "$label" --arg kind "$kind" --arg slug "$slug" --arg ver "$ver" \
          '.[] | [$site, $kind, $slug, $ver, .severity, (.score|tostring), .id, (.description|.[0:200])] | @tsv' \
          <<< "$hits" >> "$FZF_TMP" 2>/dev/null || true
      done < <(jq -c '.themes[]' "$dump_file" 2>/dev/null || true)
    done
    total_hits=$(wc -l < "$FZF_TMP")
    echo "[*] $total_hits hit(s) — opening in fzf (type to filter, Ctrl-C to quit)"
    # fzf: columns are site | type | slug | ver | severity | score | CVE-ID | description
    # shellcheck disable=SC2016
    fzf --delimiter=$'\t' \
        --header="SITE  TYPE  SLUG  VER  SEV  SCORE  CVE-ID  DESCRIPTION" \
        --preview='id=$(echo {} | cut -f7); jq -r --arg id "$id" '"'"'.[] | select(.id==$id) |
          "CVE: \(.id)\nPublished: \(.published)\nSeverity: \(.severity) / \(.score // "N/A")\n\nDescription:\n\(.description)\n\nCPEs:\n" +
          (.affected | map("  \(.vendor):\(.product)  \(if .vsi!="" then ">=\(.vsi)" else "" end)\(if .vei!="" then " <=\(.vei)" else "" end)\(if .vee!="" then " <\(.vee)" else "" end)") | join("\n")) +
          "\n\nReferences:\n" + (.references | .[0:5] | join("\n"))'"'"' '"$DB_FILE" \
        < "$FZF_TMP"
    exit 0
  fi

  # normal report (with optional --grep slug filter)
  declare -A site_summary

  run_report() {
    echo "WordPress Vulnerability Report"
    echo "Generated: $(date -u)"
    echo "Sites: ${#dump_files[@]}   CVE window: last ${DAYS} days"
    [[ -n "$GREP_PATTERN" ]] && echo "Filter: $GREP_PATTERN"
    echo ""

    for dump_file in "${dump_files[@]}"; do
      label=$(jq -r '.label // .site // "unknown"' "$dump_file")
      wp_ver=$(jq -r '.wp_version // "unknown"' "$dump_file")
      dumped=$(jq -r '.dumped_at // "unknown"' "$dump_file")
      plugin_count=$(jq '.plugins | length' "$dump_file")
      theme_count=$(jq '.themes  | length' "$dump_file")

      site_critical=0; site_high=0; site_medium=0; site_hits=0
      site_buf=""

      check_component() {
        local kind="$1" slug="$2" ver="$3"
        # --grep filters by slug name
        [[ -n "$GREP_PATTERN" ]] && ! echo "$slug" | grep -qi "$GREP_PATTERN" && return
        local hits count
        hits=$(match_component "$slug" "$ver")
        count=$(echo "$hits" | jq 'length')
        [[ "$count" -eq 0 ]] && return
        site_buf+="  [$kind] $slug $ver — $count CVE(s)\n"
        site_buf+=$(format_hit "$slug" "$ver" "$hits")
        site_hits=$((site_hits + count))
        site_critical=$((site_critical + $(echo "$hits" | jq '[.[] | select(.severity=="CRITICAL")] | length')))
        site_high=$((site_high         + $(echo "$hits" | jq '[.[] | select(.severity=="HIGH")]     | length')))
        site_medium=$((site_medium      + $(echo "$hits" | jq '[.[] | select(.severity=="MEDIUM")]  | length')))
      }

      # WordPress core (only if no --grep filter, or filter matches "wordpress")
      if [[ -z "$GREP_PATTERN" ]] || echo "wordpress" | grep -qi "$GREP_PATTERN"; then
        if [[ "$wp_ver" != "unknown" ]]; then
          hits=$(match_component "wordpress" "$wp_ver")
          count=$(echo "$hits" | jq 'length')
          if [[ "$count" -gt 0 ]]; then
            site_buf+="  [CORE] WordPress $wp_ver — $count CVE(s)\n"
            site_buf+=$(format_hit "wordpress-core" "$wp_ver" "$hits")
            site_hits=$((site_hits + count))
            site_critical=$((site_critical + $(echo "$hits" | jq '[.[] | select(.severity=="CRITICAL")] | length')))
            site_high=$((site_high         + $(echo "$hits" | jq '[.[] | select(.severity=="HIGH")]     | length')))
            site_medium=$((site_medium      + $(echo "$hits" | jq '[.[] | select(.severity=="MEDIUM")]  | length')))
          fi
        fi
      fi

      while IFS= read -r comp; do
        check_component "PLUGIN/$(jq -r '.status' <<< "$comp")" \
          "$(jq -r '.name' <<< "$comp")" "$(jq -r '.version // ""' <<< "$comp")"
      done < <(jq -c '.plugins[]' "$dump_file" 2>/dev/null || true)

      while IFS= read -r comp; do
        check_component "THEME/$(jq -r '.status' <<< "$comp")" \
          "$(jq -r '.name' <<< "$comp")" "$(jq -r '.version // ""' <<< "$comp")"
      done < <(jq -c '.themes[]' "$dump_file" 2>/dev/null || true)

      # Only print this site if it has results (or no grep filter)
      if [[ "$site_hits" -gt 0 ]] || [[ -z "$GREP_PATTERN" ]]; then
        echo "──────────────────────────────────────────────────────"
        echo "SITE: $label"
        echo "  WordPress: $wp_ver   Plugins: $plugin_count   Themes: $theme_count   Dumped: $dumped"
        echo ""
        if [[ "$site_hits" -gt 0 ]]; then
          printf "%b" "$site_buf"
          echo "  Site total: $site_hits CVE(s) — CRITICAL:$site_critical HIGH:$site_high MEDIUM:$site_medium"
        else
          echo "  No matches in current CVE window."
        fi
        echo ""
      fi

      site_summary["$label"]="CRIT:$site_critical HIGH:$site_high MED:$site_medium TOTAL:$site_hits"
    done

    echo "═══════════════════════════════════════════════════════"
    echo "SUMMARY"
    echo "═══════════════════════════════════════════════════════"
    for lbl in "${!site_summary[@]}"; do
      printf "  %-45s %s\n" "$lbl" "${site_summary[$lbl]}"
    done | sort
  }

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo " WordPress Vulnerability Report — $(date -u)"
  echo "═══════════════════════════════════════════════════════"
  echo ""

  run_report | tee "$OUTPUT"

  echo ""
  echo "[*] Report saved to $OUTPUT"
  exit 0
fi

# ── --match mode: simple slug list (backward compat) ─────────────────────────
if [[ -n "$MATCH_FILE" ]]; then
  [[ -f "$MATCH_FILE" ]] || { echo "Error: $MATCH_FILE not found"; exit 1; }
  echo ""
  echo "[*] Cross-matching against $MATCH_FILE..."
  matched=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    slug="${line%%:*}"
    version="${line#*:}"; [[ "$version" == "$slug" ]] && version=""

    hits=$(match_component "$slug" "$version")
    count=$(echo "$hits" | jq 'length')
    if [[ "$count" -gt 0 ]]; then
      matched=$((matched + 1))
      echo ""
      echo "  [MATCH] $slug${version:+ v$version} — $count CVE(s):"
      format_hit "$slug" "${version:-any}" "$hits"
    fi
  done < "$MATCH_FILE"
  echo "[*] Done — $matched component(s) with hits"
  exit 0
fi

echo ""
echo "[*] No --sites or --match specified. Run with --help for usage."
