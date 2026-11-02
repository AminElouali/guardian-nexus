import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_wheelhouse.py"
SPEC = importlib.util.spec_from_file_location("verify_wheelhouse", SCRIPT)
assert SPEC and SPEC.loader
verify_wheelhouse_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_wheelhouse_module)


class OfflineWheelhouseTests(unittest.TestCase):
    def test_accepts_exact_hash_locked_artifact_without_network(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            artifact = wheelhouse / "sample-1.0-py3-none-any.whl"
            artifact.write_bytes(b"known test wheel bytes")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            lock = root / "requirements.txt"
            lock.write_text(
                f"sample==1.0 \\\n    --hash=sha256:{digest}\n",
                encoding="utf-8",
            )

            result = verify_wheelhouse_module.verify_wheelhouse(
                wheelhouse, [lock]
            )

        self.assertFalse(result["networkUsed"])
        self.assertEqual(result["artifactCount"], 1)
        self.assertEqual(result["artifacts"][0]["filename"], artifact.name)

    def test_rejects_a_changed_artifact_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            (wheelhouse / "sample.whl").write_bytes(b"changed")
            lock = root / "requirements.txt"
            lock.write_text(
                "sample==1.0 \\\n"
                "    --hash=sha256:" + ("0" * 64) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "found 0"):
                verify_wheelhouse_module.verify_wheelhouse(
                    wheelhouse, [lock]
                )

    def test_rejects_unlocked_wheelhouse_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            artifact = wheelhouse / "sample.whl"
            artifact.write_bytes(b"known test wheel bytes")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            (wheelhouse / "unlocked.whl").write_bytes(b"extra")
            lock = root / "requirements.txt"
            lock.write_text(
                f"sample==1.0 \\\n    --hash=sha256:{digest}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unlocked files"):
                verify_wheelhouse_module.verify_wheelhouse(
                    wheelhouse, [lock]
                )


if __name__ == "__main__":
    unittest.main()
