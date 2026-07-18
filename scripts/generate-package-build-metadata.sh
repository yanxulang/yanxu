#!/bin/sh
set -eu

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [ "$#" -ne 2 ]; then
  echo "用法：scripts/generate-package-build-metadata.sh <crate> <输出>" >&2
  exit 2
fi

crate=$1
output=$2
if [ ! -f "$crate" ]; then
  echo "共享包制品不存在：$crate" >&2
  exit 2
fi

root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
metadata=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1)
version=$(printf '%s\n' "$metadata" \
  | jq -er '.packages[] | select(.name == "yanxu-package") | .version')
expected_name="yanxu-package-$version.crate"
if [ "$(basename "$crate")" != "$expected_name" ]; then
  echo "共享包制品名与版本不一致：应为 $expected_name" >&2
  exit 2
fi

commit_sha=$(git -C "$root" rev-parse HEAD)
source_epoch=$(git -C "$root" show -s --format=%ct HEAD)
workspace_lock_sha=$(sha256_file "$root/Cargo.lock")
crate_sha=$(sha256_file "$crate")
crate_bytes=$(wc -c < "$crate" | tr -d ' ')
rustc_info=$(rustc -vV)
rustc_release=$(printf '%s\n' "$rustc_info" | sed -n 's/^release: //p')
rustc_commit=$(printf '%s\n' "$rustc_info" | sed -n 's/^commit-hash: //p')
rustc_host=$(printf '%s\n' "$rustc_info" | sed -n 's/^host: //p')
cargo_release=$(cargo --version | awk '{print $2}')

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
tar -xzf "$crate" -C "$temporary"
package_root="$temporary/yanxu-package-$version"
for path in \
  "$package_root/.cargo_vcs_info.json" \
  "$package_root/Cargo.lock" \
  "$package_root/Cargo.toml" \
  "$package_root/LICENSE"; do
  if [ ! -f "$path" ]; then
    echo "共享包制品缺少必要文件：${path#"$package_root/"}" >&2
    exit 1
  fi
done

expected_dirty=${YANXU_PACKAGE_EXPECT_DIRTY:-false}
case "$expected_dirty" in
  true|false) ;;
  *) echo "YANXU_PACKAGE_EXPECT_DIRTY 只可为 true 或 false" >&2; exit 2 ;;
esac
jq -e \
  --arg commit "$commit_sha" \
  --argjson dirty "$expected_dirty" \
  '.git.sha1 == $commit and (.git.dirty // false) == $dirty
   and .path_in_vcs == "crates/yanxu-package"' \
  "$package_root/.cargo_vcs_info.json" >/dev/null

packaged_metadata=$(cargo metadata \
  --manifest-path "$package_root/Cargo.toml" \
  --no-deps \
  --offline \
  --format-version 1)
printf '%s\n' "$packaged_metadata" | jq -e \
  --arg version "$version" \
  '[.packages[] | select(.name == "yanxu-package" and .version == $version
    and .license == "MIT")] | length == 1' >/dev/null
cmp "$root/LICENSE" "$package_root/LICENSE"

crate_lock_sha=$(sha256_file "$package_root/Cargo.lock")
license_sha=$(sha256_file "$package_root/LICENSE")
mkdir -p "$(dirname "$output")"
jq -n \
  --arg version "$version" \
  --arg repository "${GITHUB_REPOSITORY:-YanXuLang/yanxu}" \
  --arg source_ref "${YANXU_SOURCE_REF:-${GITHUB_REF:-refs/tags/yanxu-package-v$version}}" \
  --arg commit_sha "$commit_sha" \
  --arg source_epoch "$source_epoch" \
  --arg artifact_name "$expected_name" \
  --arg artifact_sha "$crate_sha" \
  --argjson artifact_bytes "$crate_bytes" \
  --arg workspace_lock_sha "$workspace_lock_sha" \
  --arg crate_lock_sha "$crate_lock_sha" \
  --arg license_sha "$license_sha" \
  --arg rustc_release "$rustc_release" \
  --arg rustc_commit "$rustc_commit" \
  --arg rustc_host "$rustc_host" \
  --arg cargo_release "$cargo_release" \
  '{
    schema_version: 1,
    package: {
      name: "yanxu-package",
      version: $version,
      license: "MIT",
      path_in_vcs: "crates/yanxu-package"
    },
    source: {
      repository: $repository,
      ref: $source_ref,
      commit_sha: $commit_sha,
      commit_timestamp: ($source_epoch | tonumber)
    },
    artifact: {
      name: $artifact_name,
      format: "cargo-crate-v1",
      sha256: $artifact_sha,
      bytes: $artifact_bytes
    },
    build: {
      command: "cargo package -p yanxu-package --locked",
      locked: true,
      workspace_cargo_lock_sha256: $workspace_lock_sha,
      packaged_cargo_lock_sha256: $crate_lock_sha,
      license_sha256: $license_sha,
      rustc: {
        release: $rustc_release,
        commit_sha: $rustc_commit,
        host: $rustc_host
      },
      cargo_release: $cargo_release
    }
  }' > "$output.tmp"
mv "$output.tmp" "$output"

jq -e \
  --arg version "$version" \
  --arg commit "$commit_sha" \
  --arg crate_sha "$crate_sha" \
  --arg workspace_lock_sha "$workspace_lock_sha" \
  --arg crate_lock_sha "$crate_lock_sha" \
  '.schema_version == 1
   and .package.name == "yanxu-package" and .package.version == $version
   and .package.license == "MIT"
   and .source.commit_sha == $commit
   and .artifact.sha256 == $crate_sha and .artifact.bytes > 0
   and .build.locked
   and .build.workspace_cargo_lock_sha256 == $workspace_lock_sha
   and .build.packaged_cargo_lock_sha256 == $crate_lock_sha
   and (.build.license_sha256 | test("^[0-9a-f]{64}$"))' \
  "$output" >/dev/null
