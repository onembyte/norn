"""Generation must be deterministic: same inputs, byte-identical outputs."""
import pathlib
import tempfile
import unittest

import gen_vectors


class Deterministic(unittest.TestCase):
    def _generate(self) -> dict[str, bytes]:
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            gen_vectors._written.clear()
            gen_vectors.write_keys(out)
            gen_vectors.write_entries(out)
            gen_vectors.write_log(out)
            gen_vectors.write_genesis_aborts(out)
            gen_vectors.write_trust_rejections(out)
            gen_vectors.write_trust(out)
            return {str(p.relative_to(out)): p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}

    def test_two_runs_are_identical(self):
        self.assertEqual(self._generate(), self._generate())

    def test_expected_files_present(self):
        """Counts are derived from the fixture, never hard-coded.

        Hard-coded totals broke on every vector addition and taught nothing when
        they did; deriving them means the test still asserts the generator wrote
        one file per fixture item, and stays quiet when the fixture grows.
        """
        from nornref import entry, fixture

        files = self._generate()
        log = fixture.log()
        rejecting = [item for item in log if item.reason]

        self.assertIn("keys.json", files)
        self.assertIn("state.json", files)
        for name in ("trust.cbor", "trust.toml", "trust.fingerprint", "receipt.note",
                     "genesis/cases.json", "trust-bad/cases.json"):
            self.assertIn(name, files)

        counts = {
            "entries/*.cbor": len(fixture.catalogue()),
            "entries/*.json": len(fixture.catalogue()),
            "log/*.cbor": len(log),
            "log/*.reason": len(rejecting),
            "genesis/*/state.json": len(fixture.genesis_aborts()),
            "trust-bad/*.cbor": len(fixture.trust_rejections()),
        }
        actual = {
            "entries/*.cbor": self._count(files, "entries/", ".cbor"),
            "entries/*.json": self._count(files, "entries/", ".json"),
            "log/*.cbor": self._count(files, "log/", ".cbor"),
            "log/*.reason": self._count(files, "log/", ".reason"),
            "genesis/*/state.json": self._count(files, "genesis/", "state.json"),
            "trust-bad/*.cbor": self._count(files, "trust-bad/", ".cbor"),
        }
        self.assertEqual(actual, counts)
        self.assertEqual(len(entry.TYPES), 14, "a new entry type needs a catalogue vector")

    @staticmethod
    def _count(files, prefix: str, suffix: str) -> int:
        return len([f for f in files if f.startswith(prefix) and f.endswith(suffix)])


class NoOrphans(unittest.TestCase):
    """Generation must leave no file it did not write.

    A stale file is worse than a missing one: `log/` is a numbered sequence, so
    an orphan from a renumbering sorts *between* live entries. An implementer
    who globs the directory -- the obvious reading -- silently loads a
    different, longer, wrongly-ordered log.
    """

    def test_regeneration_prunes_stale_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            gen_vectors.main(["gen_vectors", str(out)])
            stale = out / "log" / "99-left-over.cbor"
            stale.write_bytes(b"\x00")
            (out / "trust-bad" / "99-stale.cbor").write_bytes(b"\x00")
            gen_vectors.main(["gen_vectors", str(out)])
            self.assertFalse(stale.exists(), "stale log entry survived regeneration")
            self.assertFalse((out / "trust-bad" / "99-stale.cbor").exists())

    def test_every_log_file_is_named_by_the_manifest(self):
        import json
        root = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"
        manifest = json.loads((root / "log" / "manifest.json").read_text())
        named = {e["name"] for e in manifest["entries"]}
        for suffix in (".cbor", ".reason"):
            on_disk = {p.stem for p in (root / "log").glob(f"*{suffix}")}
            self.assertEqual(on_disk - named, set(), f"orphan {suffix} files in log/")
