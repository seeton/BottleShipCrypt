#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
workspace="$script_dir/workspaces/simulated-strong-stale-root"
input_path="$workspace/plaintext.bin"
archive_path="$workspace/simulated-strong-demo.bship"
copy_path="$workspace/simulated-strong-demo-copy.bship"
store_path="$workspace/trusted-store.json"
current_output="$workspace/current.bin"
stale_output="$workspace/stale.bin"
bship=(go run ./cmd/bship)

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

rm -rf "$workspace"
mkdir -p "$workspace"
cd "$repo_root"

printf 'abcdefgh' > "$input_path"

echo "== Simulated-strong stale-root demo =="
echo "Workspace: $workspace"
echo "Input plaintext: $(cat "$input_path")"

run "${bship[@]}" seal --in "$input_path" --out "$archive_path" --threshold 4 --chunk-size 4 --mode simulated-strong --trusted-store "$store_path"
run cp "$archive_path" "$copy_path"
run "${bship[@]}" prune --archive "$archive_path" --keep 0 --mode simulated-strong --trusted-store "$store_path"

echo "-- trusted-store after prune --"
cat "$store_path"

echo
echo "+ go run ./cmd/bship decrypt --archive $copy_path --out $stale_output --mode simulated-strong --trusted-store $store_path"
set +e
stale_command_output=$("${bship[@]}" decrypt --archive "$copy_path" --out "$stale_output" --mode simulated-strong --trusted-store "$store_path" 2>&1)
stale_status=$?
set -e
printf '%s\n' "$stale_command_output"

if [[ $stale_status -eq 0 ]]; then
  echo "stale copied archive unexpectedly decrypted" >&2
  exit 1
fi
if [[ "$stale_command_output" != *"archive state does not match trusted store"* ]]; then
  echo "unexpected stale-archive error output" >&2
  exit 1
fi

run "${bship[@]}" decrypt --archive "$archive_path" --out "$current_output" --mode simulated-strong --trusted-store "$store_path"
echo "Recovered from current archive: $(cat "$current_output")"

echo
echo "Result: stale archive rejection happened because the local trusted-store simulator kept the newer root/version."
echo "This is a simulator-only rollback check, not a real trusted component."
