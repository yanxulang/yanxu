#!/bin/sh
set -eu

root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
crate_dir="$root/crates/yanxu-package"

cmp "$root/LICENSE" "$crate_dir/LICENSE"

actual=$(mktemp)
expected=$(mktemp)
trap 'rm -f "$actual" "$expected"' EXIT HUP INT TERM

cargo package \
  --manifest-path "$root/Cargo.toml" \
  -p yanxu-package \
  --locked \
  --allow-dirty \
  --list \
  | LC_ALL=C sort > "$actual"

printf '%s\n' \
  .cargo_vcs_info.json \
  Cargo.lock \
  Cargo.toml \
  Cargo.toml.orig \
  LICENSE > "$expected"

find "$crate_dir/src" -type f -name '*.rs' -print \
  | while IFS= read -r source; do
      printf '%s\n' "${source#"$crate_dir/"}"
    done \
  >> "$expected"

LC_ALL=C sort -o "$expected" "$expected"
cmp "$expected" "$actual"
