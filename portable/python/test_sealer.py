import base64
import json
import os
import subprocess
import unittest
from pathlib import Path
from sovereign_sealer import Sealer, SealerError

ROOT = Path(__file__).resolve().parents[1]
BIN = os.environ.get("SOVEREIGN_SEALER_BIN", str(ROOT / "rust" / "target" / "debug" / ("sovereign-sealer.exe" if os.name == "nt" else "sovereign-sealer")))

class PortableSealerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sealer = Sealer(BIN)
    def test_round_trip_and_wrong_password(self):
        sealed = self.sealer.seal(b"cross-language secret", "long test password", b"context")
        blob = base64.b64decode(sealed["blob_b64"], validate=True)
        self.assertEqual(self.sealer.open(blob, sealed["record"], "long test password", b"context"), b"cross-language secret")
        with self.assertRaises(SealerError):
            self.sealer.open(blob, sealed["record"], "wrong password", b"context")
    def test_rejects_unknown_operation(self):
        proc = subprocess.run([BIN], input=json.dumps({"operation":"bad","password":"x"}), text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["error"], "unsupported_operation")

if __name__ == "__main__":
    unittest.main()
