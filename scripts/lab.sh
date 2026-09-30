#!/usr/bin/env bash
# Helpers for the long-lived mytcp lab container.
set -euo pipefail
cd "$(dirname "$0")/.."

cmd="${1:-}"
shift || true

case "$cmd" in
  up)
    docker compose up -d --build
    echo "lab running. Next:  ./scripts/lab.sh shell"
    ;;
  shell)
    docker compose exec lab bash
    ;;
  down)
    docker compose down
    ;;
  smoke)
    docker compose exec lab bash scripts/smoke-linux.sh
    ;;
  logs)
    docker compose logs -f lab
    ;;
  status)
    docker compose ps
    ;;
  *)
    cat <<'EOF'
Usage: ./scripts/lab.sh <command>

  up      Build image (tools preinstalled) and start long-lived container
  shell   Interactive bash inside mytcp-lab
  smoke   Run ping + TCP echo smoke test inside the lab
  status  Show compose status
  logs    Follow container logs
  down    Stop and remove the lab container

Inside the shell:
  scripts/setup-tap.sh          # tap0 + 10.0.0.1/24
  go build -o /tmp/mytcp ./cmd/mytcp
  /tmp/mytcp -i tap0 -dump=false
  # other shell: ./scripts/lab.sh shell   then  ping / nc
EOF
    exit 1
    ;;
esac
