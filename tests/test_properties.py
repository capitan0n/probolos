"""
Property-based tests: what must hold for EVERY input, not for the examples.

Covers, across modules: descriptors and descriptors_safe, storage, protocol
and the gate's path checks, textsafe and report, rules and analyzers, trust
and ledger loading, agent and agentlink.

WHY THIS FILE EXISTS
--------------------
Everything tested here takes input someone else chose: the descriptor bytes
and strings a USB device sends, the first sectors of a medium it presents,
JSON in state files on disk, and messages on the two sockets. The rest of the
suite proves the cases its authors thought of. Here Hypothesis generates
inputs -- random, mutated from a real device's descriptors, and steered at the
characters and magic numbers that matter -- checks what the code PROMISES
rather than what it returns for one input, and when a promise breaks, shrinks
the input to the smallest one that still breaks it. The promises:

  * a parser fails only with its own error, never with an IndexError or a
    struct.error from somewhere inside it (an unexpected exception there is a
    device-controlled way into a code path nobody designed);
  * text that has been cleaned carries no control, format or direction
    character, and no stack of combining marks, whatever went in;
  * a message off a socket is either a valid message or refused;
  * a state file is either loaded into well-typed entries or reported, and
    never takes the program down with it;
  * the analysis of a device that parsed never fails, because a check that
    crashes is a check that did not run.

Optional dependency: without Hypothesis this module reports one skipped test
and the rest of the suite is unaffected (`pip install hypothesis`, or
`pip install -e '.[dev]'`).

PROFILES (environment variable HYPOTHESIS_PROFILE)
--------------------------------------------------
  dev   default; random inputs, and failing ones remembered in .hypothesis/
        so the next run tries them first
  ci    derandomized and without that database: the same inputs on every
        run, so a red build is reproducible rather than a coin toss
  deep  fifty times the inputs, for a nightly or pre-release run

No deadline in any profile: timing on a shared CI runner is noise, and a
parser that never terminates would hang the job, which its timeout reports.
Termination itself is asserted structurally instead (see the descriptor
walk): bounded output for bounded input.
"""

from __future__ import annotations

import json
import os
import struct
import tempfile
import threading
import unicodedata
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

try:
    from hypothesis import HealthCheck, example, given, settings
    from hypothesis import strategies as st
except ImportError:      # optional; see the module docstring
    st = None

from probolos import (agent as agent_mod, agentlink, analyzers, daemon,
                      descriptors, descriptors_safe, gate_server,
                      ledger as ledger_mod, protocol, report, rules, storage,
                      sysfs, textsafe, trust)
from tests._support import descriptor_blob


if st is None:

    @unittest.skip("Hypothesis is not installed: pip install hypothesis")
    class PropertyTestsNeedHypothesis(unittest.TestCase):
        def test_properties(self):
            pass

else:

    settings.register_profile(
        "dev", deadline=None, max_examples=150)
    settings.register_profile(
        "ci", deadline=None, max_examples=150, derandomize=True,
        database=None, print_blob=True)
    settings.register_profile(
        "deep", deadline=None, max_examples=7500)
    settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))

    # Generating whole disk images and writing them out is slower than the
    # health check's idea of a fast test; that is the cost of the property.
    _SLOW = [HealthCheck.too_slow, HealthCheck.data_too_large]

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    # Characters chosen because they are what a hostile descriptor string
    # would carry: C0/C1 controls (ESC, CSI), DEL, line/paragraph separators
    # that Qt and Pango break lines on, the bidi overrides and isolates, the
    # zero-width characters, a lone surrogate, private use, an unassigned
    # code point, combining marks (stacked, they spill over neighbouring
    # lines), wide CJK and an astral emoji (two columns, \\U escape), and the
    # replacement character.
    NASTY = ("\x00", "\x07", "\x08", "\x1b", "\x7f", "\x85", "\x9b",
             " ", " ", "؜", "‎", "‏", "‪",
             "‮", "⁦", "⁩", "​", "‍", "⁠",
             "﻿", "\ud800", "", "\U000e0001", "͸",
             "́", "̂", "̃", "⃝", "ः",
             "中", "\U0001f600", "�", "\\", "[", "2", "J")

    any_char = st.one_of(st.characters(exclude_categories=()),
                         st.sampled_from(NASTY))
    hostile_text = st.text(alphabet=any_char, max_size=300)

    # JSON as it can appear in a state file or on a socket: any shape.
    json_values = st.recursive(
        st.none() | st.booleans()
        | st.integers(min_value=-(2 ** 70), max_value=2 ** 70)
        | st.floats(allow_nan=True, allow_infinity=True)
        | st.text(alphabet=any_char, max_size=40),
        lambda inner: st.lists(inner, max_size=6)
        | st.dictionaries(st.text(max_size=12), inner, max_size=6),
        max_leaves=25)

    # A device descriptor, one configuration and two interfaces, as a
    # Kingston stick and a keyboard would send them: the seed the mutating
    # strategy below starts from, so that inputs get PAST the header checks
    # and into the parts of the parser random bytes never reach.
    _SEED_BLOBS = (descriptor_blob((0x08, 0x06, 0x50)),
                   descriptor_blob((0x03, 0x01, 0x01), (0x03, 0x00, 0x00)),
                   descriptor_blob((0xFF, 0x42, 0x01), (0x02, 0x02, 0x01),
                                   (0x0A, 0x00, 0x00)))

    @st.composite
    def mutated_blobs(draw):
        """A real descriptor set with bytes overwritten, cut, or added."""
        blob = bytearray(draw(st.sampled_from(_SEED_BLOBS)))
        for _ in range(draw(st.integers(min_value=0, max_value=6))):
            index = draw(st.integers(min_value=0, max_value=len(blob) - 1))
            blob[index] = draw(st.integers(min_value=0, max_value=255))
        if draw(st.booleans()):
            blob = blob[:draw(st.integers(min_value=0, max_value=len(blob)))]
        blob += draw(st.binary(max_size=64))
        return bytes(blob)

    @st.composite
    def tlv_chains(draw):
        """A valid device header, then descriptors with chosen lengths."""
        out = bytearray(_SEED_BLOBS[0][:18])
        for _ in range(draw(st.integers(min_value=0, max_value=12))):
            kind = draw(st.sampled_from([0x02, 0x04, 0x05, 0x21, 0x24,
                                         0x0B, 0x30, 0xFF]))
            payload = draw(st.binary(max_size=20))
            declared = draw(st.one_of(st.just(len(payload) + 2),
                                      st.integers(min_value=0,
                                                  max_value=255)))
            out += bytes([declared, kind]) + payload
        return bytes(out)

    descriptor_inputs = st.one_of(st.binary(max_size=600), mutated_blobs(),
                                  tlv_chains())

    _FS_MAGIC = ((3, b"NTFS    "), (3, b"EXFAT   "), (54, b"FAT12"),
                 (54, b"FAT16"), (82, b"FAT32"), (0x438, b"\x53\xef"),
                 (0x8001, b"CD001"), (0x8001, b"BEA01"), (0x8801, b"NSR02"),
                 (0x8801, b"NSR03"), (0x10040, b"_BHRfS_M"))

    @st.composite
    def disk_images(draw):
        """
        The first sectors of a medium: an MBR, a GPT and filesystem magic
        numbers where the parsers look for them, with chosen bytes around
        them. Zeros by default, so the structures are what varies.
        """
        sectors = draw(st.integers(min_value=1, max_value=140))
        data = bytearray(sectors * storage.SECTOR)
        if draw(st.booleans()):
            data[510:512] = b"\x55\xaa"
            for slot in range(4):
                if draw(st.booleans()):
                    entry = struct.pack(
                        "<BBBBBBBBII",
                        draw(st.sampled_from([0x00, 0x80, 0x7F])), 0, 0, 0,
                        draw(st.sampled_from([0x00, 0x06, 0x07, 0x0B, 0x0C,
                                              0x83, 0xEE, 0xEF, 0x05,
                                              0xFF])),
                        0, 0, 0,
                        draw(st.integers(min_value=0, max_value=2 ** 32 - 1)),
                        draw(st.integers(min_value=0, max_value=2 ** 32 - 1)))
                    data[446 + slot * 16:462 + slot * 16] = entry
        if sectors >= 3 and draw(st.booleans()):
            data[512:520] = storage.GPT_SIGNATURE
            data[520:604] = draw(st.binary(min_size=84, max_size=84))
            if draw(st.booleans()):
                struct.pack_into("<QII", data, 512 + 72, 2,
                                 draw(st.integers(min_value=0,
                                                  max_value=2 ** 32 - 1)),
                                 128)
        for offset, magic in draw(st.lists(st.sampled_from(_FS_MAGIC),
                                           max_size=3)):
            if offset + len(magic) <= len(data):
                data[offset:offset + len(magic)] = magic
        for _ in range(draw(st.integers(min_value=0, max_value=6))):
            offset = draw(st.integers(min_value=0, max_value=len(data) - 1))
            chunk = draw(st.binary(min_size=1, max_size=32))
            data[offset:offset + len(chunk)] = chunk[:len(data) - offset]
        declared = draw(st.one_of(st.none(), st.just(sectors),
                                  st.integers(min_value=0,
                                              max_value=2 ** 64)))
        return bytes(data), declared

    def _forbidden(char: str) -> bool:
        """What cleaned text must never contain (see textsafe.sanitize)."""
        return (unicodedata.category(char) in ("Cc", "Zl", "Zp", "Cf", "Cs",
                                               "Co", "Cn")
                or char in textsafe._BIDI or char in textsafe._INVISIBLE)

    def _longest_mark_run(text: str) -> int:
        longest = run = 0
        for char in text:
            if unicodedata.category(char) in ("Mn", "Mc", "Me"):
                run += 1
                longest = max(longest, run)
            else:
                run = 0
        return longest

    # ------------------------------------------------------------------
    # textsafe: the one place device text stops being dangerous
    # ------------------------------------------------------------------

    class CleanedTextIsSafe(unittest.TestCase):
        """
        sanitize() is applied once, where descriptor bytes become a string,
        and every surface downstream -- terminal, kdialog, zenity,
        notifications, the JSON log, the trust store, the ledger -- relies on
        it having been. These are the guarantees they rely on.
        """

        @given(hostile_text, st.integers(min_value=1, max_value=200))
        # A truncation that dropped an escape used to let later characters
        # through: four raw combining marks on one base, past the limit.
        @example("A" * 118 + "́" * 3 + "﻿" + "́", 126)
        def test_no_dangerous_character_survives(self, value, limit):
            text = textsafe.sanitize(value, limit).text
            self.assertFalse([c for c in text if _forbidden(c)], repr(text))
            self.assertLessEqual(_longest_mark_run(text),
                                 textsafe.MAX_COMBINING_RUN, repr(text))

        @given(st.binary(max_size=300), st.integers(min_value=1,
                                                    max_value=200))
        def test_bytes_are_cleaned_the_same_way(self, value, limit):
            result = textsafe.sanitize(value, limit)
            self.assertFalse([c for c in result.text if _forbidden(c)])
            decoded = value.decode("utf-8", errors="replace")
            self.assertEqual("�" in decoded,
                             textsafe.NOTE_UNDECODABLE in result.notes)

        @given(hostile_text, st.integers(min_value=1, max_value=200))
        @example("A" * 118 + "́" * 3 + "﻿" + "́", 126)
        @example("x" * 125 + "\x1b" + "y", 126)
        def test_a_cut_keeps_a_prefix_and_never_skips_ahead(self, value,
                                                            limit):
            """
            What is shown is the START of what the device sent, escaped. A
            cut that skipped an escape too long for the remaining room and
            kept going would show characters that were never next to each
            other -- hiding the very character that did not fit.
            """
            whole = textsafe.sanitize(value, 10 ** 9).text
            result = textsafe.sanitize(value, limit)
            if textsafe.NOTE_TRUNCATED in result.notes:
                self.assertTrue(result.text.endswith("..."))
                kept = result.text[:-3]
                self.assertLessEqual(len(kept), limit)
                self.assertTrue(whole.startswith(kept),
                                f"{kept!r} is not a prefix of {whole!r}")
            else:
                self.assertEqual(result.text, whole)
                self.assertLessEqual(len(result.text), limit)

        @given(hostile_text)
        def test_evidence_is_kept_past_the_cut(self, value):
            """A device cannot hide an escape behind 126 harmless letters."""
            notes = textsafe.sanitize("x" * 200 + value).notes
            if any(unicodedata.category(c) in ("Cc", "Zl", "Zp")
                   for c in value):
                self.assertIn(textsafe.NOTE_CONTROL, notes)
            if any(c in textsafe._BIDI for c in value):
                self.assertIn(textsafe.NOTE_BIDI, notes)

        @given(hostile_text, st.integers(min_value=1, max_value=200))
        def test_cleaning_clean_text_changes_nothing(self, value, limit):
            first = textsafe.sanitize(value, limit)
            if textsafe.NOTE_TRUNCATED not in first.notes:
                self.assertEqual(textsafe.sanitize(first.text, limit).text,
                                 first.text)

        @given(hostile_text, st.integers(min_value=3, max_value=120))
        def test_a_report_cell_never_overflows(self, value, columns):
            """fit/pad/split_width keep the report box a box."""
            text = textsafe.sanitize(value).text
            self.assertLessEqual(textsafe.display_width(
                textsafe.fit(text, columns)), columns)
            self.assertEqual(textsafe.display_width(
                textsafe.pad(text, columns)), columns)
            rows = textsafe.split_width(text, columns)
            self.assertEqual("".join(rows), text)
            for row in rows:
                self.assertTrue(textsafe.display_width(row) <= columns
                                or len(row) == 1, repr(row))

    # ------------------------------------------------------------------
    # Descriptors: the device's own account of itself
    # ------------------------------------------------------------------

    class DescriptorParsingFailsOnlyAsDesigned(unittest.TestCase):
        """
        sysfs.load_device catches DescriptorParseError and records it as a
        finding. Anything else escaping the parser is a crash path chosen by
        the device; these properties say there is none.
        """

        @given(descriptor_inputs)
        def test_parse_returns_or_refuses(self, blob):
            try:
                parsed = descriptors.parse(blob)
            except descriptors.DescriptorParseError:
                return
            head = struct.unpack_from("<BBHBBBBHHH", blob, 0)
            self.assertEqual(parsed.device.vendor_id, head[7])
            self.assertEqual(parsed.device.product_id, head[8])
            # The helpers every rule reads must hold up on whatever parsed.
            parsed.primary_interfaces()
            parsed.interface_classes()
            parsed.declared_power_ma()
            parsed.power_span()
            parsed.declared_interface_mismatch()

        @given(st.binary(max_size=600))
        def test_the_walk_terminates_and_accounts_for_every_byte(self, buf):
            """
            Each step advances by bLength >= 2, so the walk ends; every
            descriptor it yields is exactly what it declares; and they are the
            buffer from its start, with no byte skipped or invented.
            """
            seen = []
            try:
                for kind, desc in descriptors_safe.walk_descriptors(buf):
                    self.assertGreaterEqual(len(desc), 2)
                    self.assertEqual(desc[0], len(desc))
                    self.assertEqual(desc[1], kind)
                    seen.append(desc)
            except descriptors_safe.DescriptorParsingError:
                self.assertTrue(buf.startswith(b"".join(seen)))
            else:
                self.assertEqual(b"".join(seen), buf)
            self.assertLessEqual(len(seen), len(buf) // 2)

        @given(st.binary(max_size=400))
        def test_hid_report_items_fail_only_as_designed(self, buf):
            count = 0
            try:
                for _item in descriptors_safe.walk_hid_items(buf):
                    count += 1
            except descriptors_safe.DescriptorParsingError:
                pass
            self.assertLessEqual(count, descriptors_safe.MAX_HID_ITEMS)

    def _device(blob, manufacturer, product, serial):
        """A UsbDevice the way sysfs.load_device builds one from `blob`."""
        try:
            parsed, error = descriptors.parse(blob), None
        except descriptors.DescriptorParseError as exc:
            parsed, error = None, str(exc)
        return sysfs.UsbDevice(
            syspath=Path("/sys/devices/pci0000:00/usb1/1-4"), name="1-4",
            vendor_id="0951", product_id="1666",
            manufacturer=textsafe.clean(manufacturer),
            product=textsafe.clean(product), serial=textsafe.clean(serial),
            bus=1, device_num=7, speed="480", authorized=0, device_class=0,
            descriptor_set=parsed, parse_error=error, raw_descriptors=blob,
            removable="removable", instance_id=(1, 1000))

    class AnalysisNeverFailsOnWhatADeviceSends(unittest.TestCase):
        """
        analyzers.run contains a crashing check as a finding -- CRITICAL when
        the check was decisive -- so a crash is not a fail-open. It is still
        a check that did not run. For anything a device can send, none
        crashes, and the prompt built from the result renders.
        """

        @given(descriptor_inputs, hostile_text, hostile_text, hostile_text)
        def test_every_check_runs_and_the_prompt_renders(self, blob, maker,
                                                         product, serial):
            dev = _device(blob, maker, product, serial)
            findings = analyzers.run(analyzers.Context(device=dev))
            failed = [f.rule_id for f in findings
                      if f.rule_id.startswith("analyzer-failed:")]
            self.assertEqual(failed, [])
            for text in (report.render(dev, findings),
                         report.one_liner(dev, findings),
                         daemon.Probolos._agent_title(dev),
                         daemon.Probolos._agent_body(dev, findings),
                         daemon.Probolos._agent_capabilities(dev),
                         daemon.Probolos._critical_note(findings)):
                self.assertIsInstance(text, str)
            self.assertIn(daemon.Probolos._prompt_steps(dev, findings),
                          (agentlink.STEPS_ONE, agentlink.STEPS_TWO,
                           agentlink.STEPS_COUNTDOWN))

    # ------------------------------------------------------------------
    # Storage: the medium's account of itself
    # ------------------------------------------------------------------

    class MediumParsingFailsOnlyAsDesigned(unittest.TestCase):
        """
        The partition table and filesystem magic are read raw, from a medium
        the device chose, before anyone has approved it.
        """

        @given(st.binary(max_size=2048))
        def test_the_mbr_reader_is_total(self, data):
            partitions = storage.parse_mbr(data)
            self.assertLessEqual(len(partitions), 4)
            for part in partitions:
                self.assertIn(part.index, range(4))
                self.assertNotEqual(part.type_byte, 0)
                self.assertGreater(part.sectors, 0)

        @given(disk_images())
        def test_the_gpt_readers_are_bounded_by_the_bytes(self, image):
            data, _declared = image
            storage.parse_gpt_header(data)
            entries = storage.parse_gpt_entries(data)
            if entries is not None:
                room = max(0, (len(data) - 2 * storage.SECTOR)
                           // storage.GPT_ENTRY_SIZE)
                self.assertLessEqual(len(entries), room)

        @given(disk_images(), st.one_of(st.none(),
                                        st.integers(min_value=0,
                                                    max_value=2 ** 40)))
        def test_filesystem_identification_is_total(self, image, limit):
            name, note = storage.identify_filesystem(image[0], limit)
            self.assertIsInstance(name, (str, type(None)))
            self.assertIsInstance(note, (str, type(None)))

        @settings(suppress_health_check=_SLOW)
        @given(disk_images())
        def test_inspecting_a_medium_never_fails_the_scan(self, image):
            """The whole stage-4 path: read, parse, judge, render."""
            data, declared = image
            with tempfile.NamedTemporaryFile(suffix=".img") as fh:
                fh.write(data)
                fh.flush()
                with mock.patch.object(storage, "read_size_sectors",
                                       return_value=declared):
                    medium = storage.inspect(fh.name)
            self.assertIsNone(medium.error)
            findings = rules.storage_findings(medium)
            dev = _device(_SEED_BLOBS[0], "Kingston", "DataTraveler", "S1")
            ran = analyzers.run(
                analyzers.Context(device=dev, extra={"medium": medium}),
                analyzers=[analyzers.StorageAnalyzer()])
            self.assertEqual([f.rule_id for f in ran
                              if f.rule_id.startswith("analyzer-failed:")],
                             [])
            self.assertIsInstance(report.render_medium(medium, findings), str)

    # ------------------------------------------------------------------
    # The two sockets
    # ------------------------------------------------------------------

    _KINDS = (protocol.REQ_AUTHORIZE, protocol.REQ_ADMIT,
              protocol.REQ_SET_DEFAULT, protocol.REQ_OPEN_INPUT,
              protocol.REQ_OPEN_BLOCK, protocol.REQ_AUTHORIZE_INTERFACE,
              protocol.REQ_TRUST, protocol.REQ_PING)

    @st.composite
    def requests(draw):
        kind = draw(st.sampled_from(_KINDS))
        no_nul = st.text(alphabet=any_char.filter(lambda c: c != "\x00"),
                         max_size=60)
        instance = st.tuples(st.integers(min_value=0, max_value=2 ** 64),
                             st.integers(min_value=0, max_value=2 ** 64))
        if kind == protocol.REQ_TRUST:
            return protocol.Request(
                kind, path=draw(no_nul.filter(bool)),
                instance=draw(instance),
                key=draw(st.text(alphabet=any_char.filter(
                    lambda c: c != "\x00"), max_size=protocol.MAX_KEY)),
                label=draw(st.text(alphabet=any_char.filter(
                    lambda c: c != "\x00"), max_size=protocol.MAX_LABEL)))
        return protocol.Request(
            kind, path=draw(no_nul),
            value=draw(st.one_of(st.none(), st.integers())),
            instance=draw(st.one_of(st.none(), instance)))

    def _well_formed(test, req):
        test.assertIn(req.kind, _KINDS)
        test.assertIsInstance(req.path, str)
        test.assertNotIn("\x00", req.path)
        test.assertTrue(req.value is None or type(req.value) is int)
        if req.instance is not None:
            test.assertEqual(len(req.instance), 2)
            test.assertTrue(all(type(n) is int and n >= 0
                                for n in req.instance))
        for text, limit in ((req.key, protocol.MAX_KEY),
                            (req.label, protocol.MAX_LABEL)):
            if text is not None:
                test.assertIsInstance(text, str)
                test.assertNotIn("\x00", text)
                test.assertLessEqual(len(text), limit)
        if req.kind == protocol.REQ_TRUST:
            test.assertTrue(req.path)
            test.assertIsNotNone(req.instance)
            test.assertIsNotNone(req.key)
            test.assertIsNotNone(req.label)

    class TheGateTakesOnlyWellFormedRequests(unittest.TestCase):
        """
        The analyzer is untrusted, so whatever it sends the root gate is
        decoded into a well-formed request or refused with ValueError -- the
        one error the serve loop answers as "bad request".
        """

        @given(st.binary(max_size=protocol.MAX_MESSAGE + 64))
        def test_any_bytes_decode_or_are_refused(self, data):
            try:
                req = protocol.Request.decode(data)
            except ValueError:
                return
            _well_formed(self, req)

        @given(st.dictionaries(
            st.sampled_from(["kind", "path", "value", "instance", "key",
                             "label", "extra"]),
            st.one_of(json_values, st.sampled_from(_KINDS)), max_size=7))
        def test_any_json_object_decodes_or_is_refused(self, obj):
            try:
                req = protocol.Request.decode(json.dumps(obj).encode())
            except ValueError:
                return
            _well_formed(self, req)

        @given(requests())
        def test_a_valid_request_survives_the_wire(self, req):
            data = req.encode()
            if len(data) > protocol.MAX_MESSAGE:
                with self.assertRaises(ValueError):
                    protocol.Request.decode(data)
            else:
                self.assertEqual(protocol.Request.decode(data), req)

        @given(st.binary(max_size=600))
        def test_any_reply_decodes_or_is_refused(self, data):
            try:
                resp = protocol.Response.decode(data)
            except ValueError:
                return
            self.assertIn(resp.status, (protocol.OK, protocol.ERROR,
                                        protocol.DENIED))
            self.assertIsInstance(resp.detail, str)

        @given(st.text(alphabet=any_char, max_size=120))
        def test_path_checks_answer_rather_than_raise(self, path):
            """Whatever the path, the gate says yes or no; it never crashes."""
            usb = gate_server.GateServer._safe_usb_path(path)
            if usb is not None:
                self.assertTrue(str(usb).startswith(
                    gate_server.USB_REAL_PREFIX))
            node = gate_server.GateServer._safe_input_path(path)
            if node is not None:
                self.assertTrue(str(node).startswith(
                    gate_server.INPUT_PREFIX))
            disk, reason = gate_server.GateServer._check_block_path(path)
            self.assertTrue(disk is not None or reason)

    class TheAgentSocketCarriesOnlyWhatItShould(unittest.TestCase):
        """
        Both ends of the agent socket read lines the other end -- or whatever
        occupies the socket -- chose.
        """

        _ANSWERS = (agentlink.ANSWER_YES, agentlink.ANSWER_ALWAYS,
                    agentlink.ANSWER_NO, agentlink.ANSWER_UNAVAILABLE)

        @given(st.one_of(
            st.binary(max_size=300),
            st.builds(lambda obj: json.dumps(obj).encode(),
                      st.dictionaries(
                          st.sampled_from(["type", "id", "answer", "x"]),
                          st.one_of(json_values,
                                    st.sampled_from(["answer", "yes",
                                                     "always", "no",
                                                     "unavailable"]),
                                    st.just(7)), max_size=4))))
        def test_only_an_answer_to_this_question_is_an_answer(self, line):
            link = agentlink.AgentLink(Path("/nonexistent/agent.sock"),
                                       log=lambda *_a: None)
            answer = link._parse_answer(line, 7)
            self.assertIn(answer, self._ANSWERS + (None,))
            if answer is not None:
                message = json.loads(line.decode())
                self.assertEqual(message.get("type"), agentlink.MSG_ANSWER)
                self.assertEqual(message.get("id"), 7)

        @given(json_values)
        def test_wire_fields_are_clamped_or_defaulted(self, value):
            self.assertTrue(agent_mod.MIN_DIALOG_TIMEOUT
                            <= agent_mod._dialog_timeout(value)
                            <= agent_mod.MAX_DIALOG_TIMEOUT)
            self.assertTrue(10.0 <= agent_mod._countdown(value) <= 30.0)
            shown = agent_mod._as_text(value, "fallback")
            self.assertEqual(shown, value if isinstance(value, str)
                             else "fallback")

        @given(st.one_of(
            st.binary(max_size=400),
            st.builds(lambda obj: json.dumps(obj).encode(),
                      st.dictionaries(
                          st.sampled_from(["type", "id", "title", "body",
                                           "severity", "allow_always",
                                           "timeout", "steps", "countdown",
                                           "note", "capabilities"]),
                          st.one_of(json_values, st.sampled_from(
                              [agentlink.MSG_DECIDE, agentlink.MSG_NOTICE,
                               agentlink.MSG_CRITICAL, "one", "two",
                               "countdown"])),
                          max_size=11))))
        def test_the_agent_survives_any_line_and_never_approves(self, line):
            """
            Losing the agent is not a breach, but it removes the prompt, and
            the line comes off a socket whose occupant the agent does not get
            to choose. Nothing it is sent may crash it, and with no dialog
            answering, nothing it replies is an approval.
            """
            replies = []
            subject = agent_mod.Agent.__new__(agent_mod.Agent)
            subject.log = lambda *_a: None
            subject.notifier = mock.Mock(**{"available.return_value": False})
            subject.dialog = mock.Mock(**{
                "confirm.return_value": None, "choose.return_value": None,
                "notice.return_value": None,
                "confirm_countdown.return_value": None})
            subject.countdown_dialog = subject.dialog
            subject.sock = None
            subject._notice_window = threading.Lock()
            with mock.patch.object(subject, "_reply",
                                   side_effect=lambda _id, a:
                                   replies.append(a)):
                subject._handle(line)
            for answer in replies:
                self.assertNotIn(answer, (agentlink.ANSWER_YES,
                                          agentlink.ANSWER_ALWAYS))

    # ------------------------------------------------------------------
    # State files
    # ------------------------------------------------------------------

    class StateFilesLoadOrAreReported(unittest.TestCase):
        """
        The trust store decides what is admitted without a question; the
        ledger holds the history the CRITICAL rules read. Both are files on
        disk, so both are input: any content loads into well-typed entries or
        is reported, and none stops the daemon from starting -- which is what
        closes the gate.
        """

        @given(st.text(max_size=40), json_values)
        def test_a_trust_entry_is_valid_or_skipped(self, key, raw):
            entry = trust.TrustedDevice.from_raw(key, raw)
            if entry is None:
                return
            self.assertEqual(entry.key, key)
            self.assertTrue(entry.key and entry.descriptor_hash)
            self.assertIsInstance(entry.identity, str)
            self.assertIsInstance(entry.label, str)
            self.assertIsInstance(entry.note, str)
            self.assertTrue(type(entry.times_admitted) is int
                            and entry.times_admitted >= 0)
            self.assertTrue(all(isinstance(p, str) for p in entry.ports))
            # And what was accepted comes back the same through the loader.
            self.assertEqual(
                trust.TrustedDevice.from_raw(entry.key, asdict(entry)), entry)

        @given(json_values)
        def test_a_ledger_entry_is_valid_or_skipped(self, raw):
            entry = ledger_mod.Entry.from_raw(raw)
            if entry is None:
                return
            self.assertIsInstance(entry.identity, str)
            self.assertIsInstance(entry.descriptor_hash, str)
            self.assertNotEqual(entry.baseline_hash, "-")
            self.assertTrue(type(entry.times_seen) is int)
            for values in (entry.ports, entry.decisions, entry.known_hashes):
                self.assertTrue(all(isinstance(v, str) for v in values))

        @settings(suppress_health_check=_SLOW)
        @given(st.one_of(st.binary(max_size=500),
                         st.builds(lambda v: json.dumps(v).encode(),
                                   json_values),
                         st.builds(lambda devices: json.dumps(
                             {"schema": trust.SCHEMA_VERSION,
                              "devices": devices}).encode(),
                             st.dictionaries(st.text(max_size=20),
                                             json_values, max_size=4))))
        def test_any_trust_file_loads_or_is_reported(self, content):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "trusted.json"
                path.write_bytes(content)
                os.chmod(path, 0o600)
                store = trust.TrustStore(path)
            for key, entry in store.devices.items():
                self.assertIsInstance(entry, trust.TrustedDevice)
                self.assertEqual(entry.key, key)

        @settings(suppress_health_check=_SLOW)
        @given(st.one_of(st.binary(max_size=500),
                         st.builds(lambda v: json.dumps(v).encode(),
                                   json_values)))
        def test_any_ledger_file_loads_or_is_reported(self, content):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "ledger.json"
                path.write_bytes(content)
                os.chmod(path, 0o600)
                store = ledger_mod.Ledger(path)
            for entry in store.entries.values():
                self.assertIsInstance(entry, ledger_mod.Entry)


if __name__ == "__main__":
    unittest.main()
