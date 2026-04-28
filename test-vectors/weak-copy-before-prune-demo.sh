#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
workspace="$script_dir/workspaces/weak-copy-before-prune"
input_path="$workspace/plaintext.bin"
archive_path="$workspace/weak-demo.bship"
copy_path="$workspace/weak-demo-copy.bship"
left_output="$workspace/keep-0.bin"
right_output="$workspace/keep-1.bin"
combined_output="$workspace/combined.bin"
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

echo "== Weak-mode copy-before-prune demo =="
echo "Workspace: $workspace"
echo "Input plaintext: $(cat "$input_path")"

run "${bship[@]}" seal --in "$input_path" --out "$archive_path" --threshold 4 --chunk-size 4 --mode weak
run cp "$archive_path" "$copy_path"
run "${bship[@]}" prune --archive "$archive_path" --keep 0 --mode weak
run "${bship[@]}" prune --archive "$copy_path" --keep 1 --mode weak
run "${bship[@]}" decrypt --archive "$archive_path" --out "$left_output" --mode weak
run "${bship[@]}" decrypt --archive "$copy_path" --out "$right_output" --mode weak

echo "+ cat $left_output $right_output > $combined_output"
cat "$left_output" "$right_output" > "$combined_output"

echo "Recovered from original after prune: $(cat "$left_output")"
echo "Recovered from copied archive after prune: $(cat "$right_output")"
echo "Combined recovered plaintext: $(cat "$combined_output")"

if ! cmp -s "$input_path" "$combined_output"; then
  echo "combined plaintext does not match original input" >&2
  exit 1
fi

echo
echo "Result: attack succeeds in weak mode because the archive state can be copied before prune."
