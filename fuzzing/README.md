# Fuzzing Probolos

Everything Probolos parses before you have said yes comes from someone else:
descriptor bytes and HID reports from the device, sectors from its medium,
JSON from the state files, and datagrams from the unprivileged analyzer to the
root gate. This directory throws millions of malformed inputs at that code.

| file | what it is |
|---|---|
| `targets.py` | the 17 fuzz targets and their invariants (shared by both engines) |
| `heavy_fuzz.py` | coverage-guided fuzzer, **stdlib only**, multi-process |
| `fuzz_atheris.py` | the same targets under libFuzzer (optional, `pip install atheris`) |
| `seeds.py` | synthetic seeds per input kind, built from the test fixtures |
| `build_corpus.py` | seeds from your real devices (USB descriptors, HID reports, a disk) |

`tests/test_properties.py` (in CI) states the same promises and tries ~150
inputs per claim. This directory is the complement: millions of inputs,
coverage feedback, and the whole analysis path. It is not part of the test
suite or the sdist. What it has found is in `docs/QA-LOG.md` (How it was
found: fuzzing); a bug it finds gets a regression test in `tests/` like any
other.

## Quick start

```bash
# Manjaro / Arch: only pyudev, which Probolos needs anyway
sudo pacman -S python-pyudev

python fuzzing/heavy_fuzz.py --list                  # targets
python fuzzing/heavy_fuzz.py --duration 5m           # all targets, all cores
python fuzzing/heavy_fuzz.py --target protocol_request,gate_paths --duration 1h
python fuzzing/heavy_fuzz.py --duration 8h           # overnight
```

Crashes land in `fuzzing/crashes/<target>__<signature>.{bin,txt}`; the `.txt`
holds the traceback. Then (both honour `--timeout`, so a saved hang returns):

```bash
python fuzzing/heavy_fuzz.py --reproduce fuzzing/crashes/<file>.bin
python fuzzing/heavy_fuzz.py --minimize  fuzzing/crashes/<file>.bin   # -> .min.bin
```

## Seeding from real hardware (recommended once)

```bash
python fuzzing/build_corpus.py                       # USB + HID descriptors
sudo python fuzzing/build_corpus.py --disk /dev/sdX  # + a real stick's first 160 KiB
```

Only `--disk` needs root; under sudo the files are handed back to you, so
`heavy_fuzz.py` (run as yourself) can add to `corpus/queue/`.

Real seeds reach code synthetic ones may not (vendor class blocks, odd HID
report layouts). They also identify your devices: **never commit `corpus/`.**

## How `heavy_fuzz.py` works

1. Per input kind ("seed group": `descriptors`, `hid`, `disk`, `protocol`,
   `paths`, `agent`, `ledger`, `trust`, `text`, `payload`) it loads
   `corpus/<group>/`, `corpus/queue/<group>/` and the synthetic seeds.
2. Mutations: AFL-style byte ops (bit flips, interesting integers, arithmetic,
   chunk delete/duplicate/copy, splice), a per-group token dictionary
   (`b"EFI PART"`, `"authorize"`, HID item prefixes, ...), sector-aligned
   pokes for disk images, and structure-aware JSON mutation for the JSON
   inputs.
3. **Coverage** (Python 3.12+, `sys.monitoring`): each new line/branch in
   `probolos/` is reported once and then disabled, so the overhead drops to
   near zero. An input that reaches new code is kept, and saved to
   `corpus/queue/<group>/` for the other workers and the next run.
4. A crash is an unexpected exception, a broken invariant, a **hang**
   (`--timeout`, default 5 s) or **memory blow-up** (`--rss-mb`, default
   2048). Deduplicated by exception type + innermost `probolos/` frames.

## The targets

| target | input | invariant |
|---|---|---|
| `descriptors` | sysfs `descriptors` blob | only `DescriptorParseError` (what `sysfs.load_device` catches); helpers every rule reads don't fail |
| `descriptor_walk` | same | TLV walk terminates, accounts for every byte |
| `hid_report` | HID report descriptor | only `DescriptorParsingError`; item count bounded |
| `analysis` | same + hostile strings | **every analyzer runs** (a crash `analyzers.run` contains is re-raised), with and without ledger history; report and prompt render |
| `storage_mbr`, `storage_gpt`, `storage_fs` | first sectors | total; bounded by the bytes |
| `storage_inspect` | medium (real `memfd`) + lying size | whole stage 4: no error, size ≤ cap; every read it actually makes starts inside the device (or below `MAX_SEEK_OFFSET` when the size is unknown); storage analyzer runs, report renders |
| `protocol_request` | datagram to the root gate | well-formed request or `ValueError`; round-trips |
| `protocol_response` | reply | valid status or `ValueError` |
| `gate_paths` | path the analyzer names | yes/no, never raises; a yes is under `/sys/devices/`, `/dev/input/` |
| `agentlink_answer`, `agent_line` | agent socket line | only an answer to *this* question counts; agent never replies yes/always on its own |
| `ledger`, `trust` | state file | loads into well-typed entries or reports; never raises |
| `textsafe` | device string (str or bytes) | no control/bidi/invisible chars, ≤3 stacked marks, truncation keeps a prefix, report cells fit |
| `payload` | keystroke events | keystroke count exact; line count O(max_chars) |

## atheris (optional)

atheris now ships wheels for CPython 3.13 and 3.14, so no pyenv is needed:

```bash
python -m venv ~/.venvs/atheris && . ~/.venvs/atheris/bin/activate
pip install atheris pyudev
python fuzzing/build_corpus.py          # writes fuzzing/corpus/<group>/
python fuzzing/fuzz_atheris.py descriptors -max_total_time=600 -jobs=4 \
    fuzzing/corpus/descriptors
python fuzzing/fuzz_atheris.py protocol_request -max_len=8256 \
    fuzzing/corpus/protocol
```

Always give it the seed directory: from nothing, libFuzzer rarely produces
valid JSON, and the JSON targets (`protocol_request`, `ledger`, `trust`,
`agent_*`) then sit at a handful of covered edges. It writes what it finds
back into that directory.

## Adding a target

Write `target_<name>(data: bytes)` in `targets.py`: catch only the exception
the production caller catches, `assert` what the caller relies on, register it
in `TARGETS`, `SEED_GROUP` (and `seeds.py` if it is a new kind of input).
