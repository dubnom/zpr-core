#!/bin/sh
set -eu
umask 077

if [ "$(uname -s)" != Darwin ] || [ "${1:-}" != --allow-temporary-utun ] || [ "$#" -ne 1 ]; then
    echo "usage (macOS): sh macos-utun-smoke.sh --allow-temporary-utun" >&2
    echo "Creates/closes two fresh test interfaces with isolated IPv6 /128 aliases. No default-route/DNS commands." >&2
    exit 2
fi
if [ "$(id -u)" = 0 ]; then
    echo "Run as your desktop user; only the compiled test receives administrator authorization, not Cargo." >&2
    exit 2
fi
command -v jq >/dev/null || { echo "jq is required to select the exact Cargo test executable" >&2; exit 1; }
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -r -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
cd "$root"
cargo test --locked -p ph --lib --no-run --message-format=json > "$stage/build.json"
binary=$(jq -rs '[.[] | select(.reason=="compiler-artifact" and .target.name=="ph" and .profile.test==true and .executable!=null)] | if length==1 then .[0].executable else error("expected exactly one ph library test artifact") end' "$stage/build.json")
[ -f "$binary" ] && [ ! -L "$binary" ]
cp "$binary" "$stage/utun-test"
chmod 0500 "$stage/utun-test"
snapshot() {
    /usr/sbin/netstat -rn -f inet > "$stage/routes-v4-$1"
    /usr/sbin/netstat -rn -f inet6 > "$stage/routes-v6-$1"
    awk '$1=="default"{print}' "$stage/routes-v4-$1" > "$stage/default-v4-$1"
    awk '$1=="default"{print}' "$stage/routes-v6-$1" > "$stage/default-v6-$1"
    /usr/sbin/scutil --dns > "$stage/dns-$1"
    /sbin/ifconfig -l > "$stage/interfaces-$1"
}
snapshot before
status=0
test_name=sys::macos::zprtun::tests::privileged_utun_lifecycle_smoke
if sudo -n true 2>/dev/null; then
    sudo -n /usr/bin/env ZPR_MACOS_UTUN_SMOKE=1 "$stage/utun-test" \
        --exact "$test_name" --ignored --nocapture --test-threads=1 || status=$?
else
    /usr/bin/osascript - "$stage/utun-test" "$test_name" <<'APPLESCRIPT' || status=$?
on run argv
    set commandText to "/usr/bin/env ZPR_MACOS_UTUN_SMOKE=1 " & quoted form of (item 1 of argv) & " --exact " & quoted form of (item 2 of argv) & " --ignored --nocapture --test-threads=1"
    return do shell script commandText with administrator privileges
end run
APPLESCRIPT
fi
snapshot after
for item in default-v4 default-v6 dns interfaces; do
    if ! cmp -s "$stage/$item-before" "$stage/$item-after"; then
        echo "Host $item snapshot changed. Inspect the host before continuing; no automatic network repair attempted." >&2
        status=1
    fi
done
if [ "$status" -ne 0 ]; then
    echo "Mac utun smoke did not pass (or host state changed). No live ZPR credentials or adapter were started." >&2
    exit "$status"
fi
echo "Isolated native utun smoke passed; existing interfaces, IPv4/IPv6 default routes and DNS snapshots unchanged."
