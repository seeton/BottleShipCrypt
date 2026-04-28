#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

"$script_dir/weak-copy-before-prune-demo.sh"
echo
"$script_dir/simulated-strong-stale-root-demo.sh"
