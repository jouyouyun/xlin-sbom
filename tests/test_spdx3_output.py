import json
import tempfile
import unittest
from pathlib import Path

from actions.scanner import spdx_sbom_helper


def _minimal_linx_sbom():
    return {
        "packages_sbom": {
            "packages": [{
                "id": "Package-demo-abc123",
                "name": "demo",
                "version": "1.0",
                "architecture": "x86_64",
                "package_type": "rpm",
                "depends": [],
                "source": "NOASSERTION",
                "licenses": [],
                "suppliers": [],
                "description": "demo package",
                "checksum": {
                    "algorithm": "SHA1",
                    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            }]
        },
        "licenses_sbom": {"licenses": []},
        "files_sbom": {"files": []},
        "package_relationships_sbom": {"package_relationships": []},
        "file_relationships_sbom": {"file_relationships": []},
    }


class Spdx3OutputTests(unittest.TestCase):
    def test_convert_and_write_spdx3_jsonld(self):
        payload = spdx_sbom_helper.convert_to_spdx3_payload(
            _minimal_linx_sbom(),
            "demo",
            "2026-06-16T00:00:00Z",
            "rpm",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            base = str(Path(tmpdir) / "spdx3-sbom_demo")
            jsonld_path = spdx_sbom_helper.write_spdx3_payload(payload, base)
            self.assertTrue(jsonld_path.endswith(".jsonld"))
            self.assertTrue(Path(jsonld_path).exists())
            with open(jsonld_path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertIn("@context", data)
            self.assertIn("@graph", data)
            self.assertIsInstance(data["@graph"], list)
            self.assertGreater(len(data["@graph"]), 0)


if __name__ == "__main__":
    unittest.main()
