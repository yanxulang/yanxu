#!/bin/sh
set -eu

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  fi
}

if [ "$#" -ne 1 ]; then
  echo "用法：scripts/generate-sbom.sh <输出>" >&2
  exit 2
fi

output=$1
root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
version=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
  | jq -er '.packages[] | select(.name == "yanxu") | .version')
metadata=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1)
package_version=$(printf '%s\n' "$metadata" | jq -er '.packages[] | select(.name == "yanxu-package") | .version')
native_v1_version=$(printf '%s\n' "$metadata" | jq -er '.packages[] | select(.name == "yanxu-native-example") | .version')
native_v2_version=$(printf '%s\n' "$metadata" | jq -er '.packages[] | select(.name == "yanxu-native-v2-example") | .version')
commit_sha=$(git -C "$root" rev-parse HEAD)
source_epoch=$(git -C "$root" show -s --format=%ct HEAD)
lock_sha=$(sha256_file "$root/Cargo.lock")

SOURCE_DATE_EPOCH=$source_epoch cargo cyclonedx \
  --manifest-path "$root/Cargo.toml" \
  --format json \
  --target all \
  --override-filename "yanxu-$version.cdx" \
  --license-strict \
  --license-accept-named MIT/Apache-2.0 \
  --spec-version 1.5

normalize_bom() {
  input=$1
  destination=$2
  expected_name=$3
  expected_version=$4
  serial_hex=$(sha256_text "$commit_sha:$expected_name:$expected_version")
  serial_number=$(printf '%s\n' "$serial_hex" | sed -E \
    's/^(.{8})(.{4}).(.{3}).(.{3})(.{12}).*$/urn:uuid:\1-\2-8\3-a\4-\5/')
  if ! printf '%s\n' "$serial_number" | grep -Eq \
    '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'; then
    echo "不能从组件身份生成 CycloneDX 序列号" >&2
    exit 1
  fi
  test -s "$input"
  mv "$input" "$destination"
  jq \
    --arg version "$version" \
    --arg package_version "$package_version" \
    --arg native_v1_version "$native_v1_version" \
    --arg native_v2_version "$native_v2_version" \
    --arg serial_number "$serial_number" \
    --arg commit "$commit_sha" \
    --arg lock_sha "$lock_sha" \
    '
      def normalize_workspace:
        if type != "string" then .
        elif startswith("path+file:") and contains("/crates/yanxu-package#") then
          sub("path\\+file://[^#]*/crates/yanxu-package#[^ ]+";
              "pkg:cargo/yanxu-package@" + $package_version)
        elif startswith("path+file:") and contains("/examples/native-extension-rust#") then
          sub("path\\+file://[^#]*/examples/native-extension-rust#[^ ]+";
              "pkg:cargo/yanxu-native-example@" + $native_v1_version)
        elif startswith("path+file:") and contains("/examples/native-extension-v2-rust#") then
          sub("path\\+file://[^#]*/examples/native-extension-v2-rust#[^ ]+";
              "pkg:cargo/yanxu-native-v2-example@" + $native_v2_version)
        elif startswith("path+file:") and contains("#yanxu@") then
          sub("path\\+file://[^#]*#yanxu@[^ ]+"; "pkg:cargo/yanxu@" + $version)
        elif startswith("pkg:cargo/") and contains("?download_url=file://") then
          sub("\\?download_url=file://.*$"; "")
        else . end;
      walk(if type == "string" then normalize_workspace else . end)
      | .serialNumber = $serial_number
      | .metadata.properties += [
          {name: "cdx:yanxu:source:commit", value: $commit},
          {name: "cdx:yanxu:cargo-lock:sha256", value: $lock_sha},
          {name: "cdx:yanxu:build:profile", value: "release"}
        ]
    ' "$destination" > "$destination.tmp"
  mv "$destination.tmp" "$destination"

  jq -e \
    --arg name "$expected_name" \
    --arg expected_version "$expected_version" \
    --arg serial_number "$serial_number" \
    --arg commit "$commit_sha" \
    --arg lock_sha "$lock_sha" \
    '.bomFormat == "CycloneDX" and .specVersion == "1.5"
     and .serialNumber == $serial_number
     and .metadata.component.name == $name and .metadata.component.version == $expected_version
     and (.dependencies | length) > 0
     and ([.metadata.properties[] | select(.name == "cdx:yanxu:source:commit" and .value == $commit)] | length) == 1
     and ([.metadata.properties[] | select(.name == "cdx:yanxu:cargo-lock:sha256" and .value == $lock_sha)] | length) == 1
     and ([.. | strings | select(contains("path+file:") or contains("download_url=file://"))] | length) == 0' \
    "$destination" >/dev/null
  if grep -F "$root" "$destination" >/dev/null; then
    echo "SBOM 不得包含构建机绝对路径" >&2
    exit 1
  fi
}

mkdir -p "$(dirname "$output")"
normalize_bom "$root/yanxu-$version.cdx.json" "$output" "yanxu" "$version"
normalize_bom \
  "$root/crates/yanxu-package/yanxu-$version.cdx.json" \
  "$(dirname "$output")/yanxu-package-$package_version.cdx.json" \
  "yanxu-package" "$package_version"
normalize_bom \
  "$root/examples/native-extension-rust/yanxu-$version.cdx.json" \
  "$(dirname "$output")/yanxu-native-example-$native_v1_version.cdx.json" \
  "yanxu-native-example" "$native_v1_version"
normalize_bom \
  "$root/examples/native-extension-v2-rust/yanxu-$version.cdx.json" \
  "$(dirname "$output")/yanxu-native-v2-example-$native_v2_version.cdx.json" \
  "yanxu-native-v2-example" "$native_v2_version"
