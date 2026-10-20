#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <ph-adapters-linux-x86_64.tar.gz>" >&2
    exit 2
fi

archive=$1
if [[ ! -f "$archive" ]]; then
    echo "Release artifact is not a regular file: $archive" >&2
    exit 1
fi

for tool in python3 readelf grep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool not found: $tool" >&2
        exit 1
    fi
done

validation_dir=$(mktemp -d)
trap 'rm -rf -- "$validation_dir"' EXIT

python3 - "$archive" "$validation_dir" <<'PY'
import hashlib
import os
import re
import shutil
import sys
import tarfile

archive, destination = sys.argv[1:]
expected_names = {"ph", "ph-cli", "SHA256SUMS"}


def fail(message):
    print(f"Invalid Linux x86_64 release artifact: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        names = []
        for member in members:
            name = member.name
            if (
                name.startswith("/")
                or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
            ):
                fail(f"unsafe archive path: {name!r}")
            if name not in expected_names:
                fail(f"unexpected archive member: {name!r}")
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                fail(f"archive member is not a regular file: {name!r}")
            if name in names:
                fail(f"duplicate archive member: {name!r}")
            names.append(name)

        if set(names) != expected_names or len(names) != len(expected_names):
            fail(f"archive members must be exactly {sorted(expected_names)}; got {names}")

        for member in members:
            if member.name in ("ph", "ph-cli") and member.mode & 0o111 == 0:
                fail(f"binary is not executable in archive: {member.name}")
            source = bundle.extractfile(member)
            if source is None:
                fail(f"could not read archive member: {member.name}")
            target = os.path.join(destination, member.name)
            with source, open(target, "xb") as extracted:
                shutil.copyfileobj(source, extracted)
            os.chmod(target, member.mode & 0o777)
except (OSError, tarfile.TarError) as error:
    fail(f"could not read archive: {error}")

manifest_path = os.path.join(destination, "SHA256SUMS")
try:
    with open(manifest_path, "r", encoding="ascii", newline="") as manifest_file:
        lines = manifest_file.read().splitlines()
except (OSError, UnicodeError) as error:
    fail(f"could not read checksum manifest: {error}")

checksums = {}
checksum_line = re.compile(r"([0-9a-fA-F]{64})  (ph|ph-cli)")
for line in lines:
    match = checksum_line.fullmatch(line)
    if match is None:
        fail(f"invalid checksum entry: {line!r}")
    digest, name = match.groups()
    if name in checksums:
        fail(f"duplicate checksum entry: {name}")
    checksums[name] = digest.lower()

if set(checksums) != {"ph", "ph-cli"}:
    fail(f"checksum manifest must list ph and ph-cli exactly; got {sorted(checksums)}")

for name, expected_digest in checksums.items():
    digest = hashlib.sha256()
    with open(os.path.join(destination, name), "rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_digest:
        fail(f"checksum mismatch for {name}")
PY

for binary in ph ph-cli; do
    path="$validation_dir/$binary"
    if [[ ! -x "$path" ]]; then
        echo "Extracted binary is not executable: $binary" >&2
        exit 1
    fi

    header=$(readelf -h "$path") || {
        echo "Could not read ELF header from $binary" >&2
        exit 1
    }
    if ! grep -Eq 'Class:[[:space:]]+ELF64$' <<<"$header"; then
        echo "$binary is not ELF64" >&2
        exit 1
    fi
    if ! grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64$' <<<"$header"; then
        echo "$binary is not x86_64" >&2
        exit 1
    fi
done

"$validation_dir/ph" adapter --help >/dev/null
"$validation_dir/ph-cli" --help >/dev/null

echo "Validated Linux x86_64 release artifact: $archive"
