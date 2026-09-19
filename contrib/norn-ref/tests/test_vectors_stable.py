"""Generation must be deterministic: same inputs, byte-identical outputs."""
import pathlib
import tempfile
import unittest

import gen_vectors


class Deterministic(unittest.TestCase):
    def _generate(self) -> dict[str, bytes]:
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            gen_vectors.write_keys(out)
            gen_vectors.write_entries(out)
            gen_vectors.write_log(out)
            return {str(p.relative_to(out)): p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}

    def test_two_runs_are_identical(self):
        self.assertEqual(self._generate(), self._generate())

    def test_expected_files_present(self):
        files = self._generate()
        self.assertIn("keys.json", files)
        self.assertEqual(len([f for f in files if f.startswith("entries/") and f.endswith(".cbor")]), 16)
        self.assertEqual(len([f for f in files if f.startswith("log/") and f.endswith(".cbor")]), 40)
        self.assertEqual(len([f for f in files if f.endswith(".reason")]), 17)
        self.assertIn("state.json", files)
        self.assertEqual(len([f for f in files if f.startswith("entries/") and f.endswith(".json")]), 16)
