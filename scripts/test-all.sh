#!/usr/bin/env bash
set -u

# Run both suites even if one fails; preserve each real exit status.
swift_status=0
python_status=0

swift test || swift_status=$?
(
  cd infrastructure/mcp_authority &&
    python3 -m unittest discover -s tests -v
) || python_status=$?

printf '\nSwift test exit: %s\nPython dispatcher test exit: %s\n' "$swift_status" "$python_status"

if (( swift_status != 0 || python_status != 0 )); then
  exit 1
fi
