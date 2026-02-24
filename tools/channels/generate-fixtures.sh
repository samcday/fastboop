#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
out_dir="${1:-${repo_root}/build/channels-fixtures}"
seed="${FASTBOOP_CHANNEL_SEED:-fastboop-channels-v1}"
epoch="${SOURCE_DATE_EPOCH:-1700000000}"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required command: %s\n' "$1" >&2
        exit 1
    fi
}

for cmd in mkfs.erofs mkfs.ext4 mkfs.vfat python3 truncate xz zip; do
    require_cmd "${cmd}"
done

export TZ=UTC
export LC_ALL=C

work_dir="${out_dir}/.work"
tree_dir="${work_dir}/rootfs"
modules_dir="${tree_dir}/usr/lib/modules/6.9.0-fastboop/kernel/drivers/usb/gadget"

rm -rf "${out_dir}"
mkdir -p "${tree_dir}/boot" "${modules_dir}" "${tree_dir}/etc"

python3 - "${tree_dir}" "${seed}" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
seed = sys.argv[2].encode("utf-8")


def deterministic_bytes(label: str, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        chunk = hashlib.sha256(seed + b":" + label.encode("utf-8") + b":" + str(counter).encode("ascii")).digest()
        out.extend(chunk)
        counter += 1
    return bytes(out[:size])


(root / "boot" / "Image").write_bytes(deterministic_bytes("kernel-image", 4096))
(root / "usr/lib/modules/6.9.0-fastboop/modules.dep").write_text(
    "kernel/drivers/usb/gadget/dummy.ko:\n", encoding="utf-8"
)
(root / "usr/lib/modules/6.9.0-fastboop/kernel/drivers/usb/gadget/dummy.ko").write_bytes(
    deterministic_bytes("dummy-ko", 2048)
)
(root / "etc/os-release").write_text(
    "NAME=fastboop-fixtures\nVERSION=1\nID=fastboop\n", encoding="utf-8"
)
PY

find "${tree_dir}" -exec touch -h -d "@${epoch}" {} +

if ! mkfs.erofs -T "${epoch}" "${out_dir}/rootfs.erofs" "${tree_dir}" >/dev/null 2>&1; then
    rm -f "${out_dir}/rootfs.erofs"
    mkfs.erofs "${out_dir}/rootfs.erofs" "${tree_dir}" >/dev/null
fi

truncate -s 32M "${out_dir}/rootfs.ext4"
E2FSPROGS_FAKE_TIME="${epoch}" mkfs.ext4 \
    -q \
    -F \
    -d "${tree_dir}" \
    -L ROOTFS \
    -U 00000000-0000-0000-0000-000000000000 \
    "${out_dir}/rootfs.ext4"

truncate -s 64M "${out_dir}/boot.vfat"
mkfs.vfat -F 32 -n BOOT "${out_dir}/boot.vfat" >/dev/null

touch -d "@${epoch}" "${out_dir}/rootfs.erofs" "${out_dir}/rootfs.ext4" "${out_dir}/boot.vfat"

xz -f -k -T1 "${out_dir}/rootfs.erofs"
touch -d "@${epoch}" "${out_dir}/rootfs.erofs.xz"

(
    cd "${out_dir}"
    zip -X -q "rootfs.erofs.zip" "rootfs.erofs"
)
touch -d "@${epoch}" "${out_dir}/rootfs.erofs.zip"

python3 - "${out_dir}" <<'PY'
import pathlib
import struct
import sys

out_dir = pathlib.Path(sys.argv[1])

(out_dir / "profile-bundle-v1.bin").write_bytes(b"FBCH" + struct.pack("<H", 1) + b"\x00\x00" + b"fixture-profile")

sparse = bytearray(4096)
sparse[0:4] = struct.pack("<I", 0xED26FF3A)
sparse[4:6] = struct.pack("<H", 1)
sparse[6:8] = struct.pack("<H", 0)
sparse[8:10] = struct.pack("<H", 28)
sparse[10:12] = struct.pack("<H", 12)
sparse[12:16] = struct.pack("<I", 4096)
sparse[16:20] = struct.pack("<I", 1)
sparse[20:24] = struct.pack("<I", 0)
sparse[24:28] = struct.pack("<I", 0)
(out_dir / "android-sparse.img").write_bytes(sparse)

mbr = bytearray(4096)
mbr[446 + 4] = 0x83
mbr[446 + 8 : 446 + 12] = struct.pack("<I", 1)
mbr[446 + 12 : 446 + 16] = struct.pack("<I", 64)
mbr[510:512] = b"\x55\xAA"
(out_dir / "mbr.img").write_bytes(mbr)

gpt = bytearray(8192)
gpt[446 + 4] = 0xEE
gpt[446 + 8 : 446 + 12] = struct.pack("<I", 1)
gpt[446 + 12 : 446 + 16] = struct.pack("<I", 0xFFFF)
gpt[510:512] = b"\x55\xAA"
gpt[512:520] = b"EFI PART"
(out_dir / "gpt.img").write_bytes(gpt)

iso = bytearray(65536)
iso[32768] = 1
iso[32769:32774] = b"CD001"
iso[32774] = 1
(out_dir / "iso9660.img").write_bytes(iso)
PY

rm -rf "${work_dir}"

printf 'generated channel fixtures in %s\n' "${out_dir}"
