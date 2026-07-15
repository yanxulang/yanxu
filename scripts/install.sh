#!/bin/sh
set -eu

REPOSITORY="${YANXU_REPOSITORY:-YanXuLang/yanxu}"
VERSION="${YANXU_VERSION:-latest}"
INSTALL_DIR="${YANXU_INSTALL_DIR:-$HOME/.local/bin}"
ASSET_DIR="${YANXU_ASSET_DIR:-}"

say() { printf '%s\n' "$*"; }
fail() { say "言序安装失败：$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "需要命令 $1"; }
download() {
  curl --disable --fail --location --silent --show-error \
    --proto '=https' --tlsv1.2 "$@"
}
github_api() {
  if [ -n "${YANXU_GITHUB_TOKEN:-}" ]; then
    download --header "Authorization: Bearer ${YANXU_GITHUB_TOKEN}" "$@"
  else
    download "$@"
  fi
}

need tar
if [ -z "$ASSET_DIR" ]; then
  need curl
fi

case "$(uname -s)" in
  Darwin) system="apple-darwin" ;;
  Linux) system="unknown-linux-gnu" ;;
  *) fail "此脚本支持 macOS 与 Linux；Windows 请使用 install.ps1" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) fail "暂不支持处理器架构 $(uname -m)" ;;
esac

target="${arch}-${system}"
asset="yanxu-${target}.tar.gz"
checksum_asset="yanxu-${target}.sha256"
if [ -n "$ASSET_DIR" ] && [ "$VERSION" = "latest" ]; then
  fail "使用 YANXU_ASSET_DIR 时必须通过 YANXU_VERSION 指定版本"
elif [ "$VERSION" = "latest" ]; then
  release_json="$(github_api \
    --header "Accept: application/vnd.github+json" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${REPOSITORY}/releases/latest")" || fail "无法查询最新稳定发行版"
  tag="$(printf '%s' "$release_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$tag" ] || fail "仓库尚未发布可安装的稳定版本"
  base_url="https://github.com/${REPOSITORY}/releases/download/${tag}"
  version_label="最新版 ${tag}"
else
  case "$VERSION" in v*) tag="$VERSION" ;; *) tag="v$VERSION" ;; esac
  base_url="https://github.com/${REPOSITORY}/releases/download/${tag}"
  version_label="$tag"
fi

tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t yanxu)"
staged=""
cleanup() {
  rm -rf "$tmp_dir"
  [ -z "$staged" ] || rm -f "$staged"
}
trap cleanup EXIT HUP INT TERM

say "正在安装言序 ${version_label}（${target}）…"
if [ -n "$ASSET_DIR" ]; then
  [ -f "$ASSET_DIR/$asset" ] || fail "本地制品目录缺少 $asset"
  [ -f "$ASSET_DIR/$checksum_asset" ] || fail "本地制品目录缺少 $checksum_asset"
  cp "$ASSET_DIR/$asset" "$tmp_dir/$asset"
  cp "$ASSET_DIR/$checksum_asset" "$tmp_dir/$checksum_asset"
else
  download "$base_url/$asset" --output "$tmp_dir/$asset" || fail "未找到适用于 ${target} 的发行包"
  download "$base_url/$checksum_asset" --output "$tmp_dir/$checksum_asset" || fail "发行包缺少 SHA-256 校验文件"
fi

if [ -f "$tmp_dir/$checksum_asset" ]; then
  expected="$(awk '{print $1; exit}' "$tmp_dir/$checksum_asset")"
  case "$expected" in
    ''|*[!0-9A-Fa-f]*) fail "SHA-256 校验文件格式无效" ;;
  esac
  [ "${#expected}" -eq 64 ] || fail "SHA-256 校验文件格式无效"
  expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')"
  else
    fail "系统没有 sha256sum 或 shasum，无法校验下载"
  fi
  [ "$expected" = "$actual" ] || fail "SHA-256 校验不一致"
fi

mkdir -p "$INSTALL_DIR"
tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"
binary="$(find "$tmp_dir" -type f -name yanxu -perm -u+x | head -n 1)"
[ -n "$binary" ] || fail "发行包内没有 yanxu 可执行文件"
staged="$(mktemp "$INSTALL_DIR/.yanxu.XXXXXX")" || fail "无法在安装目录创建临时文件"
install -m 755 "$binary" "$staged"
if ! installed_version="$("$staged" --version 2>&1)"; then
  fail "下载的 yanxu 无法在当前系统运行：$installed_version"
fi
[ -n "$installed_version" ] || fail "下载的 yanxu 没有返回版本信息"
expected_version="言序 ${tag#v}"
[ "$installed_version" = "$expected_version" ] || fail "发行标签 ${tag} 与二进制版本不一致：${installed_version}"
mv -f "$staged" "$INSTALL_DIR/yanxu"
staged=""

say "言序已安装到 $INSTALL_DIR/yanxu"
say "已验证：$installed_version"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) say "现在可以运行 yanxu。" ;;
  *)
    say "请把以下一行加入你的 shell 配置，然后重开终端："
    say "  export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac
