#!/bin/sh
set -eu

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [ "$#" -ne 4 ]; then
  echo "用法：scripts/generate-build-metadata.sh <目标> <归档> <二进制> <输出>" >&2
  exit 2
fi

target=$1
archive=$2
binary=$3
output=$4
case "$target" in
  *[!A-Za-z0-9_.-]*) echo "目标名称含非法字符：$target" >&2; exit 2 ;;
esac
for path in "$archive" "$binary"; do
  if [ ! -f "$path" ]; then
    echo "构建输入不存在：$path" >&2
    exit 2
  fi
done

root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
version=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
  | jq -er '.packages[] | select(.name == "yanxu") | .version')
commit_sha=$(git -C "$root" rev-parse HEAD)
source_epoch=$(git -C "$root" show -s --format=%ct HEAD)
lock_sha=$(sha256_file "$root/Cargo.lock")
archive_sha=$(sha256_file "$archive")
binary_sha=$(sha256_file "$binary")
archive_bytes=$(wc -c < "$archive" | tr -d ' ')
binary_bytes=$(wc -c < "$binary" | tr -d ' ')
rustc_info=$(rustc -vV)
rustc_release=$(printf '%s\n' "$rustc_info" | sed -n 's/^release: //p')
rustc_commit=$(printf '%s\n' "$rustc_info" | sed -n 's/^commit-hash: //p')
rustc_host=$(printf '%s\n' "$rustc_info" | sed -n 's/^host: //p')
cargo_release=$(cargo --version | awk '{print $2}')
runtime_info=$("$binary" version --json)

jq -e \
  --arg version "$version" \
  --arg commit "$commit_sha" \
  --arg target "$target" \
  '.version == $version and .commit_sha == $commit and .build_target == $target and .build_mode == "release"' \
  >/dev/null <<EOF
$runtime_info
EOF

mkdir -p "$(dirname "$output")"
jq -n \
  --arg version "$version" \
  --arg commit_sha "$commit_sha" \
  --arg source_ref "${YANXU_SOURCE_REF:-${GITHUB_REF:-refs/tags/v$version}}" \
  --arg repository "${GITHUB_REPOSITORY:-YanXuLang/yanxu}" \
  --arg source_epoch "$source_epoch" \
  --arg target "$target" \
  --arg archive_name "$(basename "$archive")" \
  --arg archive_sha "$archive_sha" \
  --argjson archive_bytes "$archive_bytes" \
  --arg binary_name "$(basename "$binary")" \
  --arg binary_sha "$binary_sha" \
  --argjson binary_bytes "$binary_bytes" \
  --arg lock_sha "$lock_sha" \
  --arg rustc_release "$rustc_release" \
  --arg rustc_commit "$rustc_commit" \
  --arg rustc_host "$rustc_host" \
  --arg cargo_release "$cargo_release" \
  --argjson runtime "$runtime_info" \
  '{
    schema_version: 1,
    version: $version,
    source: {
      repository: $repository,
      ref: $source_ref,
      commit_sha: $commit_sha,
      commit_timestamp: ($source_epoch | tonumber)
    },
    artifact: {
      name: $archive_name,
      sha256: $archive_sha,
      bytes: $archive_bytes
    },
    binary: {
      name: $binary_name,
      sha256: $binary_sha,
      bytes: $binary_bytes,
      version_info: $runtime
    },
    build: {
      target: $target,
      profile: "release",
      locked: true,
      cargo_lock_sha256: $lock_sha,
      rustc: {
        release: $rustc_release,
        commit_sha: $rustc_commit,
        host: $rustc_host
      },
      cargo_release: $cargo_release
    }
  }' > "$output.tmp"
mv "$output.tmp" "$output"

jq -e --arg target "$target" --arg version "$version" --arg commit "$commit_sha" \
  '.schema_version == 1 and .version == $version and .source.commit_sha == $commit
   and .build.target == $target and .build.profile == "release" and .build.locked
   and (.artifact.sha256 | test("^[0-9a-f]{64}$"))
   and (.binary.sha256 | test("^[0-9a-f]{64}$"))
   and (.build.cargo_lock_sha256 | test("^[0-9a-f]{64}$"))' "$output" >/dev/null
