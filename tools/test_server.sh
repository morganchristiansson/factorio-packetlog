#!/bin/sh
# One throwaway Factorio server for the observer client: base mod only, no auth.
# The real install at /factorio (its mods, saves) is never touched: read-data
# is /factorio/data, write-data is a fresh RUN_DIR created from scratch each run,
# so every start is identical (fixed map seed).
#
# Factorio closes stdout when stdin is EOF, so its own stdout/stderr are thrown
# away and factorio-current.log is printed to OUR stdout instead — that's what
# the process tool captures. Killing this script kills factorio too.
#
# Env knobs: RUN_DIR / PORT / RCON_PORT / RCON_PASSWORD
set -eu

RUN_DIR="${RUN_DIR:-/tmp/factorio-server}"
PORT="${PORT:-34197}"
RCON_PORT="${RCON_PORT:-27016}"
RCON_PASSWORD="${RCON_PASSWORD:-test}"

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/mods" "$RUN_DIR/saves" "$RUN_DIR/temp"

cat > "$RUN_DIR/mods/mod-list.json" <<'EOF'
{
  "mods":
  [
    { "name": "base", "enabled": true },
    { "name": "elevated-rails", "enabled": false },
    { "name": "quality", "enabled": false },
    { "name": "space-age", "enabled": false }
  ]
}
EOF

cat > "$RUN_DIR/server-settings.json" <<'EOF'
{
  "name": "test-server",
  "description": "observer test",
  "tags": ["test"],
  "max_players": 10,
  "visibility": { "public": false, "lan": true },
  "require_user_verification": false,
  "autosave_interval": 0,
  "auto_pause": true,
  "non_blocking_saving": true,
  "allow_commands": "admins-only"
}
EOF

cat > "$RUN_DIR/config.ini" <<EOF
[path]
read-data=/factorio/data
write-data=$RUN_DIR

[other]
; non_blocking_saving tested separately; keep the log one file
no-log-rotation=true
verbose-logging=true
EOF
/factorio/bin/x64/factorio \
  --config "$RUN_DIR/config.ini" \
  --start-server-load-scenario base/freeplay \
  --map-gen-seed 42 \
  --port "$PORT" \
  --rcon-port "$RCON_PORT" \
  --rcon-password "$RCON_PASSWORD" \
  --server-settings "$RUN_DIR/server-settings.json" \
  >/dev/null 2>&1 &
FPID=$!
trap 'kill "$FPID" 2>/dev/null || true' EXIT INT TERM

LOG="$RUN_DIR/factorio-current.log"
i=0
while [ ! -f "$LOG" ] && [ "$i" -lt 200 ]; do sleep 0.1; i=$((i + 1)); done
tail -n +1 -F "$LOG"