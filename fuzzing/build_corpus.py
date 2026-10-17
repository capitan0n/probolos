"""
Seed the corpus from this machine's real devices, plus the synthetic seeds.

    python fuzzing/build_corpus.py                      # -> fuzzing/corpus/
    sudo python fuzzing/build_corpus.py --disk /dev/sdX # + a real medium

Layout: corpus/<group>/*.bin, one directory per input kind (see
targets.SEED_GROUP). What it collects:

  descriptors  /sys/bus/usb/devices/*/descriptors       (device + config)
  hid          /sys/bus/hid/devices/*/report_descriptor  (HID report items)
  disk         the first 160 KiB of --disk DEVICE, read-only, never mounted
  (all)        seeds.py's synthetic seeds, so every group has some

The sysfs files are world-readable, so only --disk needs root. Under sudo,
what this creates is handed back to the user who ran sudo: heavy_fuzz.py,
run as that user, has to write into corpus/queue/.

PRIVACY: real seeds carry your devices' VID:PID and, with --disk, the start
of that medium (partition table, boot sector, maybe a volume label). Keep
corpus/ out of git -- it is in .gitignore.
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

DISK_BYTES = 160 * 1024


def _owner():
    """(uid, gid) of the user behind sudo, or None when not under sudo."""
    if os.geteuid() != 0:
        return None
    try:
        return int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return None


def _hand_back(path: Path) -> None:
    owner = _owner()
    if owner is not None:
        os.chown(path, *owner, follow_symlinks=False)


def _save(out: Path, group: str, name: str, data: bytes) -> bool:
    if not data:
        return False
    d = out / group
    for directory in (out, d):
        if not directory.exists():
            directory.mkdir(parents=True)
            _hand_back(directory)
    digest = hashlib.blake2b(data, digest_size=6).hexdigest()
    target = d / f"{name}_{digest}.bin"
    if target.exists():
        return False
    target.write_bytes(data)
    _hand_back(target)
    print(f"  {group:12} {name}: {len(data)} B")
    return True


def _read_all(pattern_root: Path, attr: str):
    if not pattern_root.is_dir():
        return
    for entry in sorted(pattern_root.iterdir()):
        f = entry / attr
        try:
            yield entry.name, f.read_bytes()
        except OSError:
            continue


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("out", nargs="?", default=str(HERE / "corpus"))
    ap.add_argument("--disk", metavar="DEVICE",
                    help="also seed 'disk' from the start of this block "
                         "device (read-only)")
    ap.add_argument("--no-synthetic", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    saved = 0

    for name, data in _read_all(Path("/sys/bus/usb/devices"), "descriptors"):
        saved += _save(out, "descriptors", name, data)
    for name, data in _read_all(Path("/sys/bus/hid/devices"),
                                "report_descriptor"):
        saved += _save(out, "hid", name.replace(":", "_"), data)
    if args.disk:
        fd = os.open(args.disk, os.O_RDONLY | os.O_CLOEXEC)
        try:
            saved += _save(out, "disk", Path(args.disk).name,
                           os.pread(fd, DISK_BYTES, 0))
        finally:
            os.close(fd)

    if not args.no_synthetic:
        import seeds
        for group in seeds.GENERATORS:
            for i, data in enumerate(seeds.for_group(group)):
                saved += _save(out, group, f"synthetic{i:02d}", data)

    print(f"\n{saved} new seed(s) in {out}/")
    if os.geteuid() != 0 and args.disk:
        print("(not root: reading --disk usually needs sudo)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
