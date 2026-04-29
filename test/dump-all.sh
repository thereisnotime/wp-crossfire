#!/usr/bin/env bash
# dump-all.sh — run wp-dump.sh against every running test container
# Output goes to dumps/<container>.json
#
# Usage:
#   ./dump-all.sh                   # dump all containers
#   ./dump-all.sh wp59 wp64         # dump specific containers only
#   ./dump-all.sh | xargs ...       # pipe dump paths to another tool
#
# After dumping, run the cross-match from the repo root:
#   ../wp-vulns.sh --sites dumps/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUMP_SCRIPT="$SCRIPT_DIR/../wp-dump.sh"
DUMPS_DIR="$SCRIPT_DIR/dumps"
COMPOSE_CMD="${COMPOSE_CMD:-podman compose}"

ALL_CONTAINERS=(wp59 wp60 wp64 wp66 wplatest)
TARGET_CONTAINERS=("${@:-${ALL_CONTAINERS[@]}}")

mkdir -p "$DUMPS_DIR"

[[ -f "$DUMP_SCRIPT" ]] || { echo "Error: $DUMP_SCRIPT not found"; exit 1; }

for container in "${TARGET_CONTAINERS[@]}"; do
  echo -n "[$container] "

  # Check it's actually running
  if ! $COMPOSE_CMD ps "$container" 2>/dev/null | grep -q "running\|Up"; then
    echo "not running — skipping"
    continue
  fi

  out="$DUMPS_DIR/${container}.json"

  # Docker Compose v2+ doesn't reliably forward stdin with exec -T,
  # so copy the script into the container and execute it there.
  $COMPOSE_CMD cp "$DUMP_SCRIPT" "${container}:/tmp/wp-dump.sh" 2>/dev/null
  $COMPOSE_CMD exec -T "$container" bash /tmp/wp-dump.sh --site "$container" \
    > "$out" 2>/tmp/wp-dump-err-"$container".txt || true

  # Sanity check — valid JSON with a wp_version field
  if jq -e '.wp_version' "$out" &>/dev/null; then
    wp_ver=$(jq -r '.wp_version' "$out")
    plugin_count=$(jq '.plugins | length' "$out")
    theme_count=$(jq '.themes | length' "$out")
    echo "ok  WP $wp_ver  plugins=$plugin_count  themes=$theme_count  → $out"
  else
    echo "failed (invalid output in $out)"
    rm -f "$out"
  fi
done

echo ""
echo "Dumps in $DUMPS_DIR:"
ls -lh "$DUMPS_DIR"/*.json 2>/dev/null || echo "  (none)"
