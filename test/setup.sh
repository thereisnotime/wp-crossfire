#!/usr/bin/env bash
# setup.sh — install WP core + a set of common plugins in each test container
# Run once after: podman compose up -d
#
# Override plugin list: PLUGINS="slug1 slug2 ..." ./setup.sh

set -euo pipefail

COMPOSE_CMD="${COMPOSE_CMD:-podman compose}"

# ~30 widely-deployed plugins across common categories, all with CVE history
PLUGINS="${PLUGINS:-
  woocommerce
  easy-digital-downloads
  the-events-calendar

  elementor
  beaver-builder-lite-version

  wordpress-seo
  all-in-one-seo-pack
  rank-math-seo

  wordfence
  all-in-one-wp-security-and-firewall
  sucuri-scanner
  really-simple-ssl

  contact-form-7
  wpforms-lite
  ninja-forms
  forminator

  jetpack
  akismet
  classic-editor
  advanced-custom-fields
  wp-mail-smtp
  redirection

  updraftplus
  duplicator
  backwpup

  w3-total-cache
  wp-super-cache
  litespeed-cache

  nextgen-gallery
  learnpress
}"
WP_ADMIN_USER="admin"
WP_ADMIN_PASS="admin"
WP_ADMIN_EMAIL="admin@test.local"

# container name → site URL
declare -A SITES=(
  [wp59]="http://localhost:8059"
  [wp60]="http://localhost:8060"
  [wp64]="http://localhost:8064"
  [wp66]="http://localhost:8066"
  [wplatest]="http://localhost:8080"
)

wpcli() {
  local container="$1"; shift
  $COMPOSE_CMD exec -T "$container" bash -c "$*"
}

install_wpcli() {
  local container="$1"
  echo "  installing WP-CLI..."
  wpcli "$container" '
    if ! command -v wp &>/dev/null; then
      curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
      chmod +x wp-cli.phar
      mv wp-cli.phar /usr/local/bin/wp
    fi
  '
}

wait_for_container() {
  local container="$1"
  local max=30 i=0
  echo -n "  waiting for $container"
  until $COMPOSE_CMD exec -T "$container" curl -sf http://localhost/ &>/dev/null; do
    echo -n "."
    sleep 3
    i=$((i+1))
    [[ $i -ge $max ]] && { echo " timed out"; return 1; }
  done
  echo " ready"
}

for container in "${!SITES[@]}"; do
  url="${SITES[$container]}"
  echo ""
  echo "=== $container ($url) ==="

  # Check container is running
  $COMPOSE_CMD ps "$container" 2>/dev/null | grep -q "running\|Up" || {
    echo "  not running — skipping (run: podman compose up -d $container)"
    continue
  }

  wait_for_container "$container"
  install_wpcli "$container"

  # Install WordPress core if not already done
  if ! wpcli "$container" "wp --allow-root core is-installed 2>/dev/null"; then
    echo "  running wp core install..."
    wpcli "$container" "wp --allow-root core install \
      --url='$url' \
      --title='Test WP ($container)' \
      --admin_user='$WP_ADMIN_USER' \
      --admin_password='$WP_ADMIN_PASS' \
      --admin_email='$WP_ADMIN_EMAIL' \
      --skip-email"
  else
    echo "  WP core already installed"
  fi

  # Install and activate plugins
  echo "  installing plugins: $PLUGINS"
  for plugin in $PLUGINS; do
    if ! wpcli "$container" "wp --allow-root plugin is-installed '$plugin' 2>/dev/null"; then
      wpcli "$container" "wp --allow-root plugin install '$plugin' --activate 2>&1 | tail -2" || \
        echo "  warning: failed to install $plugin"
    else
      wpcli "$container" "wp --allow-root plugin activate '$plugin' 2>/dev/null" || true
      echo "  $plugin already installed"
    fi
  done

  echo "  done"
done

echo ""
echo "All done. Run ./dump-all.sh to export inventories."
