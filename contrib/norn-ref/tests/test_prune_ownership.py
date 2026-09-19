"""The suite has two generators; pruning must respect the boundary.

`make vectors` deleted `served/` and `proofs/` -- eleven files produced by the
Go generator -- every time it ran, because prune removed anything this run had
not written. The two-provenance split (SPEC §12) had reached `vectors-check`
and not the generator. These tests pin the boundary rather than the memory of
having fixed it once.
"""
import pathlib
import tempfile
import unittest

import gen_vectors


class Ownership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        gen_vectors._written.clear()

    def _touch(self, rel: str) -> pathlib.Path:
        path = self.out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        return path

    def test_foreign_files_survive(self):
        served = self._touch("served/checkpoint")
        bundle = self._touch("proofs/pi-cam.bundle")
        gen_vectors.write_keys(self.out)

        gen_vectors.prune(self.out)

        self.assertTrue(served.exists(), "the Go generator's log was deleted")
        self.assertTrue(bundle.exists(), "the Go generator's bundles were deleted")

    def test_owned_orphans_are_removed(self):
        orphan = self._touch("entries/99-left-over.cbor")
        gen_vectors.write_entries(self.out)

        removed = gen_vectors.prune(self.out)

        self.assertFalse(orphan.exists())
        self.assertIn(orphan, removed)

    def test_an_unclaimed_path_stops_the_run(self):
        # A new directory from either side must force a decision, not silently
        # escape pruning: that is how the orphans of 0.13 survived three runs.
        self._touch("witness-cosignatures/0.note")
        gen_vectors.write_keys(self.out)

        with self.assertRaises(SystemExit) as caught:
            gen_vectors.prune(self.out)
        self.assertIn("witness-cosignatures", str(caught.exception))

    def test_the_two_halves_do_not_overlap(self):
        self.assertEqual(gen_vectors.OWNED & gen_vectors.FOREIGN, frozenset())


if __name__ == "__main__":
    unittest.main()
