#!/usr/bin/env bash
set -euo pipefail
echo 'The audit-only project has been superseded by the gateway. Building and testing it now.'
exec "$(dirname "$0")/build-gateway.sh"
