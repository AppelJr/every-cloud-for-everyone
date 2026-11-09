#!/usr/bin/env bash
set -euo pipefail

# Run both real suites. Missing toolchains, compile errors, and failed
# assertions stop execution and preserve a non-zero exit status.
swift test
(
  cd infrastructure/mcp_authority
  python3 -m unittest discover -s tests -v
)
