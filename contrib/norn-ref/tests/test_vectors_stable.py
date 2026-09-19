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
        files = self._generate()
        self.assertIn("keys.json", files)
        self.assertEqual(len([f for f in files if f.startswith("entries/") and f.endswith(".cbor")]), 16)
        self.assertEqual(len([f for f in files if f.startswith("log/") and f.endswith(".cbor")]), 59)
        self.assertEqual(len([f for f in files if f.endswith(".reason")]), 30)
        self.assertIn("state.json", files)
        for name in ("trust.cbor", "trust.toml", "trust.fingerprint", "receipt.note",
                     "genesis/cases.json", "trust-bad/cases.json"):
            self.assertIn(name, files)
        self.assertEqual(len([f for f in files if f.startswith("genesis/")
                              and f.endswith("state.json")]), 6)
        self.assertEqual(len([f for f in files if f.startswith("trust-bad/")
                              and f.endswith(".cbor")]), 10)
        self.assertEqual(len([f for f in files if f.startswith("entries/") and f.endswith(".json")]), 16)


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
