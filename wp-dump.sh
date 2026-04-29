#!/usr/bin/env bash
# wp-dump.sh — inventory a WordPress site for vulnerability cross-matching
# No installation required; only uses wp-cli (must already be present on site)
#
# Usage:
#   wp-dump.sh                              # WP in current dir
#   wp-dump.sh --path /var/www/html         # explicit WP root
#   wp-dump.sh --site mysite.com            # label for report (default: hostname)
#   ssh user@host 'bash -s' < wp-dump.sh > dumps/mysite.json
#   ssh user@host 'bash -s -- --site prod1' < wp-dump.sh > dumps/prod1.json
#
# Batch across many hosts (parallel, 10 at a time):
#   while read host; do
#     ssh -o StrictHostKeyChecking=no "$host" 'bash -s' < wp-dump.sh > "dumps/${host}.json" &
#     (( $(jobs -r | wc -l) >= 10 )) && wait -n
#   done < hosts.txt
#   wait

set -euo pipefail

# ── prerequisite checks ───────────────────────────────────────────────────────
require_tool() {
  local name="$1" min="$2" actual="$3"
  if [[ -z "$actual" ]]; then
    echo '{"error":"'"$name"' is required but not found (need >= '"$min"')"}' >&2; exit 1
  fi
  if ! printf '%s\n%s\n' "$min" "$actual" | sort -V -C 2>/dev/null; then
    echo '{"error":"'"$name"' '"$actual"' is too old (need >= '"$min"')"}' >&2; exit 1
  fi
}

if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo '{"error":"bash '"${BASH_VERSION}"' is too old (need >= 4.0)"}' >&2; exit 1
fi
require_tool curl 7.0 "$(curl --version 2>/dev/null | head -1 | awk '{print $2}')"
require_tool jq  1.6 "$(jq --version 2>/dev/null | sed 's/jq-//')"

WP_PATH="."
SITE_LABEL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) WP_PATH="$2"; shift 2 ;;
    --site) SITE_LABEL="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# Locate wp-cli
WP=""
for candidate in wp /usr/local/bin/wp /usr/bin/wp ~/wp-cli.phar; do
  if command -v "$candidate" &>/dev/null 2>&1 || [[ -f "$candidate" && -x "$candidate" ]]; then
    WP="$candidate"
    break
  fi
done
[[ -z "$WP" ]] && { echo '{"error":"wp-cli not found on this host"}'; exit 1; }
wp_cli_ver=$("$WP" --allow-root cli version 2>/dev/null | awk '{print $NF}' || true)
require_tool wp 2.0 "$wp_cli_ver"

_wp() { "$WP" --path="$WP_PATH" --allow-root --no-color "$@" 2>/dev/null; }

wp_version=$(_wp core version 2>/dev/null || echo "unknown")
site_url=$(_wp option get siteurl 2>/dev/null || echo "")
[[ -z "$SITE_LABEL" ]] && SITE_LABEL="${site_url:-$(hostname 2>/dev/null || echo unknown)}"

plugins=$(_wp plugin list --fields=name,version,status --format=json 2>/dev/null || echo '[]')
themes=$(_wp theme list  --fields=name,version,status --format=json 2>/dev/null || echo '[]')

jq -n \
  --arg  site     "$site_url" \
  --arg  label    "$SITE_LABEL" \
  --arg  wp_ver   "$wp_version" \
  --arg  dumped   "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson plugins "$plugins" \
  --argjson themes  "$themes" \
  '{
    site:       $site,
    label:      $label,
    wp_version: $wp_ver,
    dumped_at:  $dumped,
    plugins:    $plugins,
    themes:     $themes
  }'
