"""
Coverage-guided fuzzer for Probolos. Stdlib only, Python 3.10+ (coverage
guidance needs 3.12+, which has sys.monitoring; older Pythons fuzz blind).

    # quick smoke test, all targets
    python fuzzing/heavy_fuzz.py --iterations 200000

    # overnight, seeded from your real devices (see build_corpus.py)
    python fuzzing/heavy_fuzz.py --corpus fuzzing/corpus --duration 8h

    # one target, e.g. the root gate's request decoder
    python fuzzing/heavy_fuzz.py --target protocol_request --duration 30m

    # replay / shrink a crash
    python fuzzing/heavy_fuzz.py --reproduce fuzzing/crashes/<file>.bin
    python fuzzing/heavy_fuzz.py --minimize  fuzzing/crashes/<file>.bin

How it works
------------
1. Seeds per input kind: every file in corpus/<group>/ and
   corpus/queue/<group>/ (atheris' extensionless finds included), plus
   seeds.py's synthetic seeds.
2. Each worker picks a target, a corpus entry, and applies 1-6 mutations
   (AFL-style byte ops, dictionary tokens, splices, and structure-aware JSON
   mutation for the JSON inputs).
3. sys.monitoring reports lines/branches inside probolos/ never seen before.
   An input that reaches new code joins the corpus (and is saved to
   corpus/queue/<group>/, shared with the other workers and the next run).
   Each location is reported once and then disabled, so the overhead falls
   to near zero once coverage saturates.
4. An exception the target does not expect, a broken invariant, a hang
   (--timeout) or a memory blow-up (--rss-mb) is a crash: input and
   traceback go to crashes/, deduplicated by exception type + the innermost
   probolos frames.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import queue
import random
import re
import resource
import shutil
import signal
import struct
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
for p in (str(REPO), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

PKG_DIR = str(REPO / "probolos") + os.sep


# ---------------------------------------------------------------------------
# mutations
# ---------------------------------------------------------------------------

INTERESTING_8 = [0, 1, 0x7F, 0x80, 0xFF, 2, 9, 18, 0x40, 0x10, 0x20]
INTERESTING_16 = [0, 0x80, 0xFF, 0x100, 0x200, 0x7FFF, 0x8000, 0xFFFF, 512,
                  1024, 4096]
INTERESTING_32 = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 34, 2048,
                  0x10000, 0xFFFFFFFE]


def m_bit_flip(d, rng, _ctx):
    if not d:
        return d
    b = bytearray(d)
    i = rng.randrange(len(b))
    b[i] ^= 1 << rng.randrange(8)
    return bytes(b)


def m_random_byte(d, rng, _ctx):
    if not d:
        return d
    b = bytearray(d)
    b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def m_arith(d, rng, _ctx):
    if len(d) < 4:
        return d
    b = bytearray(d)
    i = rng.randrange(len(b) - 3)
    size = rng.choice((1, 2, 4))
    order = rng.choice(("little", "big"))
    v = int.from_bytes(b[i:i + size], order)
    v = (v + rng.randrange(-35, 36)) % (1 << (8 * size))
    b[i:i + size] = v.to_bytes(size, order)
    return bytes(b)


def m_interesting(d, rng, _ctx):
    if not d:
        return d
    b = bytearray(d)
    size = rng.choice((1, 2, 4))
    if len(b) < size:
        size = 1
    i = rng.randrange(len(b) - size + 1)
    v = rng.choice({1: INTERESTING_8, 2: INTERESTING_16,
                    4: INTERESTING_32}[size])
    b[i:i + size] = v.to_bytes(size, rng.choice(("little", "big")))
    return bytes(b)


def m_set_length_byte(d, rng, _ctx):
    """Descriptor-aware: hit a bLength (or any byte) with 0/1/2/huge."""
    if len(d) < 2:
        return d
    b = bytearray(d)
    b[rng.randrange(len(b) - 1)] = rng.choice((0, 1, 2, 3, 0xFF, 0xFE, 9, 7))
    return bytes(b)


def m_delete(d, rng, _ctx):
    if len(d) < 2:
        return d
    n = rng.randrange(1, min(len(d), 64) + 1)
    i = rng.randrange(len(d) - n + 1)
    return d[:i] + d[i + n:]


def m_duplicate(d, rng, _ctx):
    if not d:
        return d
    n = rng.randrange(1, min(len(d), 64) + 1)
    i = rng.randrange(len(d) - n + 1)
    j = rng.randrange(len(d) + 1)
    return d[:j] + d[i:i + n] + d[j:]


def m_copy_over(d, rng, _ctx):
    if len(d) < 4:
        return d
    n = rng.randrange(1, min(len(d) // 2, 64) + 1)
    i = rng.randrange(len(d) - n + 1)
    j = rng.randrange(len(d) - n + 1)
    return d[:j] + d[i:i + n] + d[j + n:]


def m_truncate(d, rng, _ctx):
    if len(d) < 2:
        return d
    return d[:rng.randrange(1, len(d))]


def m_extend(d, rng, _ctx):
    return d + rng.randbytes(rng.randrange(1, 64))


def m_token_insert(d, rng, ctx):
    tokens = ctx["tokens"]
    if not tokens:
        return m_extend(d, rng, ctx)
    t = rng.choice(tokens)
    i = rng.randrange(len(d) + 1)
    return d[:i] + t + d[i:]


def m_token_overwrite(d, rng, ctx):
    tokens = ctx["tokens"]
    if not tokens or not d:
        return m_random_byte(d, rng, ctx)
    t = rng.choice(tokens)
    if len(t) >= len(d):
        return t
    i = rng.randrange(len(d) - len(t) + 1)
    return d[:i] + t + d[i + len(t):]


def m_splice(d, rng, ctx):
    other = rng.choice(ctx["corpus"])
    if not d or not other:
        return d or other
    return d[:rng.randrange(len(d) + 1)] + other[rng.randrange(len(other)):]


def m_sector_poke(d, rng, ctx):
    """Disk-aware: write a token/integer at a sector- or field-aligned spot,
    where partition tables and superblocks actually live."""
    if len(d) < 512:
        return m_interesting(d, rng, ctx)
    b = bytearray(d)
    sector = rng.randrange(len(b) // 512)
    field = rng.choice((0, 3, 11, 54, 82, 446, 454, 458, 462, 470, 474, 510,
                        8, 24, 32, 40, 48, 72, 80, 84, 1, 6, 80, 128, 156))
    i = sector * 512 + field
    if rng.random() < 0.5 and ctx["tokens"]:
        v = rng.choice(ctx["tokens"])
    else:
        v = struct.pack("<I", rng.choice(INTERESTING_32
                                         + [rng.randrange(1 << 32)]))
    b[i:i + len(v)] = v
    return bytes(b[:len(d)])


BYTE_MUTATIONS = [m_bit_flip, m_random_byte, m_arith, m_interesting,
                  m_set_length_byte, m_delete, m_duplicate, m_copy_over,
                  m_truncate, m_extend, m_token_insert, m_token_overwrite]


# --- structure-aware JSON mutation -----------------------------------------

def _rand_json_scalar(rng, ctx):
    r = rng.random()
    if r < 0.15:
        return None
    if r < 0.25:
        return rng.choice((True, False))
    if r < 0.5:
        return rng.choice((0, -1, 1, 7, 2 ** 31, 2 ** 63, 2 ** 64, -2 ** 70,
                           10 ** 30, 0.5, float("inf"), float("nan"), -0.0))
    if r < 0.6:
        return [] if rng.random() < 0.5 else {}
    words = [t.decode("utf-8", "replace").strip('"')
             for t in ctx["tokens"]] or ["x"]
    return rng.choice(words + ["", "\x00", "‮", "\ud800", "A" * 600,
                               "/sys/devices/../../etc", "yes", "always"])


def _json_paths(obj, prefix=()):
    yield prefix
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _json_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _json_paths(v, prefix + (i,))


def m_json(d, rng, ctx):
    try:
        obj = json.loads(d)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return m_token_insert(d, rng, ctx)
    paths = list(_json_paths(obj))
    path = rng.choice(paths)
    action = rng.random()
    if not path:
        obj = _rand_json_scalar(rng, ctx) if action < 0.1 else obj
    else:
        parent = obj
        for k in path[:-1]:
            parent = parent[k]
        key = path[-1]
        if action < 0.45:
            parent[key] = _rand_json_scalar(rng, ctx)
        elif action < 0.6:
            del parent[key]
        elif action < 0.75:
            parent[key] = [parent[key]] if rng.random() < 0.5 \
                else {"x": parent[key]}
        elif action < 0.9 and isinstance(parent, dict):
            name = _rand_json_scalar(rng, ctx)
            parent[name if isinstance(name, str) else str(name)] = \
                parent[key]
        else:
            parent[key] = (rng.choice(ctx["json_corpus"])
                           if ctx["json_corpus"] else None)
    try:
        out = json.dumps(obj, allow_nan=True).encode()
    except (ValueError, RecursionError):
        return d
    if rng.random() < 0.1:                      # occasionally break syntax
        out = m_truncate(out, rng, ctx)
    return out


def mutate(data, rng, ctx):
    n = rng.choice((1, 1, 1, 2, 2, 3, 4, 6))
    for _ in range(n):
        r = rng.random()
        if r < 0.05 and ctx["corpus"]:
            data = m_splice(data, rng, ctx)
        elif ctx["json"] and r < 0.45:
            data = m_json(data, rng, ctx)
        elif ctx["disk"] and r < 0.45:
            data = m_sector_poke(data, rng, ctx)
        else:
            data = rng.choice(BYTE_MUTATIONS)(data, rng, ctx)
    return data[:ctx["max_size"]]


# ---------------------------------------------------------------------------
# coverage (sys.monitoring, Python 3.12+)
# ---------------------------------------------------------------------------

class Coverage:
    """Records each new line / branch inside probolos/ once, then disables
    that location so the steady-state cost is ~zero."""

    def __init__(self):
        self.enabled = False
        self.new = 0
        self.total = 0
        self._branches = {}
        mon = getattr(sys, "monitoring", None)
        if mon is None:
            return
        for tool in (mon.COVERAGE_ID, 3, 4, 5):
            try:
                mon.use_tool_id(tool, "probolos-fuzz")
                self.tool = tool
                break
            except ValueError:
                continue
        else:
            return
        ev = mon.events
        self.mon = mon
        mon.register_callback(tool, ev.LINE, self._line)
        events = ev.LINE
        if hasattr(ev, "BRANCH_LEFT"):           # 3.14+
            mon.register_callback(tool, ev.BRANCH_LEFT, self._edge)
            mon.register_callback(tool, ev.BRANCH_RIGHT, self._edge)
            events |= ev.BRANCH_LEFT | ev.BRANCH_RIGHT
        else:                                    # 3.12 / 3.13
            mon.register_callback(tool, ev.BRANCH, self._branch)
            events |= ev.BRANCH
        mon.set_events(tool, events)
        self.enabled = True

    def _line(self, code, _line):
        if code.co_filename.startswith(PKG_DIR):
            self.new += 1
            self.total += 1
        return self.mon.DISABLE

    def _edge(self, code, _src, _dst):
        if code.co_filename.startswith(PKG_DIR):
            self.new += 1
            self.total += 1
        return self.mon.DISABLE

    def _branch(self, code, src, dst):
        # Pre-3.14 BRANCH: DISABLE turns off both directions of the branch,
        # so keep it on until both have been seen.
        if not code.co_filename.startswith(PKG_DIR):
            return self.mon.DISABLE
        seen = self._branches.setdefault((code, src), set())
        if dst not in seen:
            seen.add(dst)
            self.new += 1
            self.total += 1
        return self.mon.DISABLE if len(seen) >= 2 else None

    def take(self) -> int:
        n, self.new = self.new, 0
        return n


# ---------------------------------------------------------------------------
# crash handling
# ---------------------------------------------------------------------------

class Hang(BaseException):
    """BaseException, so a target's `except Exception` cannot swallow it."""


def _on_alarm(_signum, _frame):
    raise Hang("input took longer than --timeout")


def _digest(data: bytes) -> str:
    """Content key for dedup (not security)."""
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def signature(target: str, exc: BaseException) -> str:
    """Exception type + innermost probolos frames: stable across inputs,
    unlike the message (which usually embeds input bytes)."""
    frames = traceback.extract_tb(exc.__traceback__)
    ours = [f for f in frames if f.filename.startswith(PKG_DIR)] or frames
    key = "|".join(f"{Path(f.filename).name}:{f.lineno}:{f.name}"
                   for f in ours[-3:])
    if isinstance(exc, Hang):
        key = "hang"
    elif isinstance(exc, MemoryError):
        key = "oom|" + key
    raw = f"{target}|{type(exc).__name__}|{key}"
    return _digest(raw.encode())[:12]


def save_crash(crash_dir: Path, target: str, data: bytes,
               exc: BaseException) -> Path:
    sig = signature(target, exc)
    path = crash_dir / f"{target}__{sig}.bin"
    if not path.exists():
        path.write_bytes(data)
        tb = "".join(traceback.format_exception(type(exc), exc,
                                                exc.__traceback__))
        path.with_suffix(".txt").write_text(
            f"target:    {target}\n"
            f"exception: {type(exc).__name__}: {str(exc)[:500]}\n"
            f"input:     {len(data)} bytes\n"
            f"reproduce: python fuzzing/heavy_fuzz.py --reproduce {path}\n\n"
            f"{tb}\n"
            f"head: {data[:256].hex()}\n")
    return path


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------

def _inputs_in(directory: Path, pattern: str = "*"):
    """Regular, non-hidden files: heavy_fuzz writes .bin, atheris (libFuzzer)
    writes extensionless SHA-1 names, and both are corpus."""
    for f in sorted(directory.glob(pattern)):
        if f.is_file() and not f.name.startswith("."):
            yield f


def load_group(corpus_dir, group):
    """Seeds for one group: every file in corpus/<group>/ and
    corpus/queue/<group>/, the flat corpus/*.bin of the original layout
    (= descriptors), plus seeds.py's synthetic seeds, always."""
    import seeds as seeds_mod
    found = []
    if corpus_dir:
        base = Path(corpus_dir)
        dirs = [(base / group, "*"), (base / "queue" / group, "*")]
        if group == "descriptors":
            dirs.append((base, "*.bin"))
        for d, pattern in dirs:
            if d.is_dir():
                for f in _inputs_in(d, pattern):
                    try:
                        found.append(f.read_bytes())
                    except OSError:
                        continue
    return found + seeds_mod.for_group(group)


def _json_values(corpus):
    """Parsed JSON values from the seeds, spliced in by m_json."""
    out = []
    for c in corpus[:64]:
        try:
            out.append(json.loads(c))
        except (ValueError, UnicodeDecodeError, RecursionError):
            pass
    return out


# ---------------------------------------------------------------------------
# worker
# ---------------------------------------------------------------------------

def _cap_memory(rss_mb):
    """The --rss-mb cap, so a memory blow-up is a MemoryError, not swap."""
    if rss_mb:
        lim = rss_mb * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
        except (ValueError, OSError):
            pass


def worker(wid, args, targets, stats_q, stop_at):
    for p in (str(REPO), str(HERE)):
        if p not in sys.path:
            sys.path.insert(0, p)
    _cap_memory(args.rss_mb)
    signal.signal(signal.SIGINT, signal.SIG_IGN)     # parent handles Ctrl-C
    signal.signal(signal.SIGALRM, _on_alarm)

    import targets as T                              # imports probolos
    rng = random.Random(args.seed + wid)
    crash_dir = Path(args.crash_dir)
    queue_root = Path(args.corpus) / "queue" if args.corpus else None

    pools, ctxs = {}, {}
    for name in targets:
        group = T.SEED_GROUP[name]
        if group not in pools:
            pools[group] = load_group(args.corpus, group)
        corpus = pools[group]
        ctxs[name] = {
            "corpus": corpus, "group": group,
            "tokens": T.DICTIONARY.get(group, []),
            "json": group in T.JSON_GROUPS, "disk": group == "disk",
            "max_size": T.MAX_SIZE.get(group, T.DEFAULT_MAX_SIZE),
            "json_corpus": _json_values(corpus) if group in T.JSON_GROUPS
            else [],
        }
    known = {g: {_digest(c) for c in pools[g]}
             for g in pools}

    cov = Coverage() if not args.no_coverage else None
    # Warm-up: run every seed once so the seeds' own coverage is not
    # credited to the first mutants.
    for name in targets:
        for s in ctxs[name]["corpus"]:
            try:
                signal.setitimer(signal.ITIMER_REAL, args.timeout)
                T.TARGETS[name](s)
            except BaseException as exc:             # noqa: BLE001
                if isinstance(exc, KeyboardInterrupt):
                    raise
                save_crash(crash_dir, name, s, exc)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
    if cov:
        cov.take()

    seen, synced = set(), set()
    execs = crashes = added = 0
    last_report = last_sync = time.time()
    per_worker = args.iterations // args.workers if args.iterations else None

    while True:
        if per_worker is not None and execs >= per_worker:
            break
        if stop_at and execs % 256 == 0 and time.time() >= stop_at:
            break
        name = rng.choice(targets)
        ctx = ctxs[name]
        corpus = ctx["corpus"]
        # Favour recent finds: they are where new coverage is being made.
        if len(corpus) > 32 and rng.random() < 0.4:
            base = corpus[rng.randrange(max(0, len(corpus) - 32), len(corpus))]
        else:
            base = rng.choice(corpus)
        try:
            data = mutate(base, rng, ctx)
        except Exception:                                # noqa: BLE001
            # A bug in the fuzzer, not in Probolos: report once, keep going.
            if "mutator" not in seen:
                seen.add("mutator")
                traceback.print_exc()
            continue
        execs += 1
        try:
            signal.setitimer(signal.ITIMER_REAL, args.timeout)
            T.TARGETS[name](data)
        except (Exception, Hang) as exc:
            signal.setitimer(signal.ITIMER_REAL, 0)
            sig = signature(name, exc)
            if sig not in seen:
                seen.add(sig)
                crashes += 1
                save_crash(crash_dir, name, data, exc)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

        if cov and cov.take():
            h = _digest(data)
            group = ctx["group"]
            if h not in known[group]:
                known[group].add(h)
                corpus.append(data)
                added += 1
                if queue_root:
                    try:
                        q = queue_root / group
                        q.mkdir(parents=True, exist_ok=True)
                        (q / f"{h[:16]}.bin").write_bytes(data)
                    except OSError as exc:
                        # e.g. a corpus/ created by `sudo build_corpus.py`:
                        # keep fuzzing, just without the shared queue.
                        print(f"\nworker {wid}: cannot write the corpus "
                              f"queue ({exc}); continuing without it",
                              file=sys.stderr)
                        queue_root = None

        now = time.time()
        if queue_root and now - last_sync > 10:          # import others' finds
            last_sync = now
            for group, pool in pools.items():
                q = queue_root / group
                if not q.is_dir():
                    continue
                for f in _inputs_in(q):
                    if f.name in synced:
                        continue
                    synced.add(f.name)
                    try:
                        b = f.read_bytes()
                    except OSError:
                        continue
                    h = _digest(b)
                    if h not in known[group]:
                        known[group].add(h)
                        pool.append(b)
        if now - last_report >= 1.0:
            last_report = now
            stats_q.put((wid, execs, crashes, added,
                         cov.total if cov else 0))
    stats_q.put((wid, execs, crashes, added, cov.total if cov else 0))


# ---------------------------------------------------------------------------
# reproduce / minimize
# ---------------------------------------------------------------------------

def _target_of(path: Path, explicit):
    if explicit and explicit != "all":
        return explicit
    stem = path.stem[:-len(".min")] if path.stem.endswith(".min") \
        else path.stem                                      # --minimize output
    m = re.match(r"(.+?)__[0-9a-f]{12}$", stem) or \
        re.match(r"(.+?)_[0-9a-f]{12}$", stem)           # old naming
    if not m:
        sys.exit("cannot tell the target from the file name; pass --target")
    return m.group(1)


def reproduce(path: Path, target, timeout, rss_mb=0):
    import targets as T
    _cap_memory(rss_mb)              # what the fuzzer ran under, or an OOM
    signal.signal(signal.SIGALRM, _on_alarm)   # replays as "no crash"
    name = _target_of(path, target)
    data = path.read_bytes()
    print(f"target {name}, {len(data)} bytes")
    try:
        signal.setitimer(signal.ITIMER_REAL, timeout)
        T.TARGETS[name](data)
    except Hang:
        print(f"hang reproduced: still running after {timeout:g}s "
              f"(--timeout)")
        return 1
    except BaseException:                                # noqa: BLE001
        traceback.print_exc()
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print("no crash (fixed, or depends on state/timing)")
    return 0


def minimize(path: Path, target, timeout, rss_mb=0):
    """Delta-debugging: drop chunks while the SAME crash signature remains."""
    import targets as T
    _cap_memory(rss_mb)
    signal.signal(signal.SIGALRM, _on_alarm)
    name = _target_of(path, target)
    fn = T.TARGETS[name]

    def sig_of(d):
        try:
            signal.setitimer(signal.ITIMER_REAL, timeout)
            fn(d)
        except BaseException as exc:                     # noqa: BLE001
            if isinstance(exc, KeyboardInterrupt):
                raise
            return signature(name, exc)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        return None

    data = path.read_bytes()
    want = sig_of(data)
    if want is None:
        print("does not crash; nothing to minimize")
        return 1
    # Media and descriptor sets keep their structures at fixed strides
    # (sectors, 2 KiB volume descriptors). Deleting whole aligned blocks
    # first shrinks them without moving what follows off its alignment,
    # which the halving pass below almost never manages.
    for block in (4096, 2048, 512):
        i = 0
        while i + block <= len(data) and len(data) > block:
            cand = data[:i] + data[i + block:]
            if sig_of(cand) == want:
                data = cand
            else:
                i += block
    chunk = max(1, len(data) // 2)
    while chunk >= 1:
        i, changed = 0, False
        while i < len(data):
            cand = data[:i] + data[i + chunk:]
            if cand != data and sig_of(cand) == want:
                data, changed = cand, True
            else:
                i += chunk
        if not changed:
            chunk //= 2
    # Then try zeroing bytes, which makes the interesting ones stand out.
    for i in range(len(data)):
        if data[i]:
            cand = data[:i] + b"\x00" + data[i + 1:]
            if sig_of(cand) == want:
                data = cand
    out = path.with_name(path.stem + ".min.bin")
    out.write_bytes(data)
    print(f"{path.stat().st_size} -> {len(data)} bytes: {out}")
    print(data.hex())
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _duration(text):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", text)
    if not m:
        raise argparse.ArgumentTypeError("e.g. 90s, 30m, 8h")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600,
                                "d": 86400}[m.group(2)]


def main():
    import targets as T
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("corpus_pos", nargs="?", help=argparse.SUPPRESS)
    ap.add_argument("--corpus", default=str(HERE / "corpus"),
                    help="corpus dir (default: fuzzing/corpus)")
    ap.add_argument("--target", default="all",
                    help="comma list of: " + ", ".join(T.TARGETS) + ", all")
    ap.add_argument("--iterations", type=int, default=None)
    ap.add_argument("--duration", type=_duration, default=None,
                    help="e.g. 90s, 30m, 8h (default 60s if no --iterations)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--crash-dir", default=str(HERE / "crashes"))
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="seconds per input before it counts as a hang")
    ap.add_argument("--rss-mb", type=int, default=2048,
                    help="address-space cap per worker (0 = none)")
    ap.add_argument("--no-coverage", action="store_true",
                    help="blind fuzzing (no sys.monitoring)")
    ap.add_argument("--reproduce", type=Path, metavar="FILE")
    ap.add_argument("--minimize", type=Path, metavar="FILE")
    ap.add_argument("--list", action="store_true", help="list targets")
    args = ap.parse_args()
    if args.corpus_pos:
        args.corpus = args.corpus_pos

    if args.list:
        for name in T.TARGETS:
            doc = " ".join((T.TARGETS[name].__doc__ or "").split())
            first = re.split(r"(?<=\.)\s", doc, maxsplit=1)[0]
            print(f"  {name:18} [{T.SEED_GROUP[name]:11}] {first}")
        return 0
    if args.reproduce:
        return reproduce(args.reproduce, args.target, args.timeout,
                         args.rss_mb)
    if args.minimize:
        return minimize(args.minimize, args.target, args.timeout,
                        args.rss_mb)

    targets = list(T.TARGETS) if args.target == "all" else \
        [t.strip() for t in args.target.split(",")]
    bad = [t for t in targets if t not in T.TARGETS]
    if bad:
        ap.error(f"unknown target(s): {bad}")
    if args.iterations is None and args.duration is None:
        args.duration = 60.0
    if args.seed is None:
        args.seed = int(time.time())
    Path(args.crash_dir).mkdir(parents=True, exist_ok=True)

    cov_note = ("coverage-guided" if sys.version_info >= (3, 12)
                and not args.no_coverage else "BLIND (no sys.monitoring)")
    print(f"targets:  {', '.join(targets)}")
    print(f"workers:  {args.workers}   mode: {cov_note}   seed: {args.seed}")
    print(f"corpus:   {args.corpus}   crashes: {args.crash_dir}")
    print("limit:    " + (f"{args.iterations:,} iterations"
                           if args.iterations else f"{args.duration:.0f}s"))

    stop_at = time.time() + args.duration if args.duration else None
    # The ledger and trust targets need real files in a private directory.
    # Workers make theirs inside this one, and the parent removes it at the
    # end: a worker's own cleanup does not run when it is terminated, nor on
    # Python 3.10, whose fork children leave through os._exit.
    work_dir = tempfile.mkdtemp(prefix="probolos-fuzz-")
    os.environ["PROBOLOS_FUZZ_TMP"] = work_dir
    stats_q = mp.Queue()
    procs = [mp.Process(target=worker, args=(i, args, targets, stats_q,
                                             stop_at), daemon=True)
             for i in range(args.workers)]
    for p in procs:
        p.start()
    state = {i: (0, 0, 0, 0) for i in range(args.workers)}
    start = time.time()
    try:
        while any(p.is_alive() for p in procs) or not stats_q.empty():
            try:
                wid, *vals = stats_q.get(timeout=0.5)
                state[wid] = tuple(vals)
            except queue.Empty:
                pass
            ex = sum(v[0] for v in state.values())
            el = max(time.time() - start, 1e-9)
            n_crash = len(list(Path(args.crash_dir).glob("*.txt")))
            sys.stdout.write(
                f"\r  {ex:>11,} execs  {ex / el:>8,.0f}/s  "
                f"new-corpus {sum(v[2] for v in state.values()):>5}  "
                f"cov(max/worker) {max(v[3] for v in state.values()):>6}  "
                f"crashes {n_crash:>3}  {el:>6.0f}s ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\ninterrupted, stopping workers")
        for p in procs:
            p.terminate()
    dead = 0
    for p in procs:
        p.join()
        if p.exitcode not in (0, None, -signal.SIGTERM):
            dead += 1
            print(f"\nworker exited with {p.exitcode} (traceback above; "
                  f"-9 = OOM killer, -11 = a crash in C code)")
    shutil.rmtree(work_dir, ignore_errors=True)

    files = sorted(Path(args.crash_dir).glob("*.txt"))
    print(f"\n\n{'=' * 64}\n{sum(v[0] for v in state.values()):,} execs in "
          f"{time.time() - start:.0f}s; crash files: {len(files)}")
    for f in files[:30]:
        first = f.read_text().split("\n")[1]
        print(f"  {f.stem}: {first[len('exception: '):][:90]}")
    return 1 if files or dead else 0


if __name__ == "__main__":
    sys.exit(main())
