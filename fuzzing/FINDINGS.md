# Findings

## 1. `storage._udf_vrs_problem`: IndexError on a buffer ending at a descriptor's version byte

- **Found by:** `heavy_fuzz.py`, target `storage_fs`, ~5 min into the first
  15-minute campaign (4 workers, ~3 M execs).
- **Where:** `probolos/storage.py`, `_udf_vrs_problem()`:

  ```python
  ident = data[off + 1:off + 6]
  if len(ident) < 5 or ident not in UDF_VRS_IDS:   # proves bytes up to off+5
      break
  if ident != ISO9660_ID and (data[off] != 0 or data[off + 6] != 1):  # reads off+6
  ```

  The length check proves the bytes up to `off + 5` exist; the next line
  reads `off + 6`. A buffer that ends exactly there raises `IndexError`.
- **Minimal repro:**

  ```python
  from probolos import storage
  storage.identify_filesystem(bytes(0x8001) + b"NSR02")   # IndexError
  ```

- **Impact: low.** Every caller of the sniffers runs inside
  `inspect_safely()`'s forked worker, which turns any exception into a
  stage-4 error report (fail closed, no daemon crash). And a real block
  device returns sector-aligned reads, so `len(data) == off + 6` (with `off`
  2048-aligned) cannot happen through `pread` on hardware. It still breaks
  the module's stated contract ("a parser fails only with its own error"),
  and `tests/test_properties.py` missed it only because its disk images are
  always whole sectors.
- **Fix:** `findings/udf-vrs-bounds.patch` -- check `len(data) < off + 7` before
  reading the descriptor, plus a Hypothesis `@example` regression in
  `tests/test_properties.py`. Verified: the example fails without the fix,
  and the full suite (1297 tests) passes with it.

## 2. Bugs in the original fuzzing harness (fixed here)

These made the old setup report nothing even where it could have:

| file | problem | effect |
|---|---|---|
| `heavy_fuzz.py` `target_trust` | temp file in `/tmp` (mode 1777) | the trust store refuses the directory before reading a byte; **the target never parsed anything** |
| `heavy_fuzz.py` `target_descriptors` | also allowed `DescriptorParsingError` | `sysfs.load_device` catches only `DescriptorParseError`, so this would have *hidden* a real crash |
| `heavy_fuzz.py` `target_storage_gpt` | swallowed `AttributeError` | hides genuine bugs |
| `heavy_fuzz.py` `mutate_overwrite_magic` | `random.choice` instead of `rng.choice` | runs not reproducible with `--seed` |
| `heavy_fuzz.py` | no hang/memory detection | an infinite loop silently freezes a worker forever |
| `heavy_fuzz.py` | crash signature includes the exception *message* | messages embed input bytes, so one bug becomes thousands of "unique" crashes |
| `heavy_fuzz.py` | blind (no coverage feedback), ledger/trust fed USB blobs | almost never valid JSON, so the loaders' logic was never reached |
| `property_tests.py` | `test_a_partition_past_end...` filters with `assume()` | fails Hypothesis' `filter_too_much` health check every run |
| `property_tests.py` | hand-written `_Device` fake | can pass while the real `UsbDevice` would not |
| `README.md` | "atheris won't build on 3.13/3.14" | atheris 3.1.0 ships wheels for both |
| (missing) | no target for the gate protocol, HID reports, filesystems, agent socket, or the analyzer pipeline | the root boundary and the rule engine were never fuzzed |
