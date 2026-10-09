#!/bin/sh
set -eu
umask 077

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: build-adapter-pkg.sh version output.pkg [--development-unsigned]" >&2
    exit 2
fi
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo "build this package on Apple Silicon macOS" >&2
    exit 2
fi

version=$1
output_file=$2
installer_identity=${ZPR_MACOS_INSTALLER_IDENTITY:-}
if [ "$#" -eq 3 ] && [ "$3" != --development-unsigned ]; then
    echo "the only supported third argument is --development-unsigned" >&2
    exit 2
fi
if [ -z "$installer_identity" ] && [ "$#" -ne 3 ]; then
    echo "set ZPR_MACOS_INSTALLER_IDENTITY or explicitly pass --development-unsigned" >&2
    exit 2
fi
if [ -n "$installer_identity" ] && [ "$#" -eq 3 ]; then
    echo "do not combine installer signing with --development-unsigned" >&2
    exit 2
fi
case "$version" in
    ''|*[!A-Za-z0-9.+-]*) echo "invalid package version" >&2; exit 2 ;;
esac
case "$output_file" in
    /*) ;;
    *) output_file="$PWD/$output_file" ;;
esac
[ ! -e "$output_file" ] || { echo "refusing to overwrite $output_file" >&2; exit 1; }
output_directory=$(dirname "$output_file")
mkdir -p "$output_directory"

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
target=aarch64-apple-darwin
binary_dir="$project_root/target/$target/release"

cd "$project_root"
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --locked --release --target "$target" -p ph -p ph-cli
for binary in ph ph-cli; do
    binary_file="$binary_dir/$binary"
    [ -x "$binary_file" ] || { echo "missing native binary: $binary_file" >&2; exit 1; }
    [ "$(/usr/bin/lipo -archs "$binary_file")" = arm64 ] || { echo "$binary is not an arm64-only binary" >&2; exit 1; }
done

install_root="$stage/root/Library/Application Support/ZPR/Adapter"
mkdir -p "$install_root/bin" "$stage/root/Library/LaunchDaemons" "$stage/scripts"
install -m 0755 "$binary_dir/ph" "$install_root/bin/ph"
install -m 0755 "$binary_dir/ph-cli" "$install_root/bin/ph-cli"
install -m 0644 "$script_dir/adapter.example.toml" "$install_root/adapter.example.toml"
install -m 0644 "$script_dir/com.zpr.ph.adapter.plist" \
    "$stage/root/Library/LaunchDaemons/com.zpr.ph.adapter.plist"
install -m 0755 "$script_dir/scripts/preinstall" "$stage/scripts/preinstall"
install -m 0755 "$script_dir/scripts/postinstall" "$stage/scripts/postinstall"

pkg_arguments=(
    --root "$stage/root"
    --scripts "$stage/scripts"
    --identifier com.zpr.ph.adapter
    --version "$version"
    --install-location /
)
if [ -n "$installer_identity" ]; then
    pkg_arguments+=(--sign "$installer_identity")
fi
/usr/bin/pkgbuild "${pkg_arguments[@]}" "$output_file"
echo "Built $(if [ -n "$installer_identity" ]; then printf 'signed'; else printf 'unsigned development'; fi) adapter package: $output_file"