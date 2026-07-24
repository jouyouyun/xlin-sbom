import json
import tempfile
import unittest
from pathlib import Path

from actions.scanner import spdx_sbom_helper
from actions.spdx.validation.document_validator import validate_full_spdx_document


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


class Spdx23OutputTests(unittest.TestCase):
    def test_convert_to_spdx_document_spdx23_validates(self):
        document = spdx_sbom_helper.convert_to_spdx_document(
            _minimal_linx_sbom(),
            "demo",
            "2026-06-16T00:00:00Z",
            "rpm",
            spdx_version="SPDX-2.3",
        )
        self.assertEqual(document.creation_info.spdx_version, "SPDX-2.3")
        self.assertEqual(
            validate_full_spdx_document(document, "SPDX-2.3"),
            [],
        )

    def test_md5_only_files_drop_dangling_contains_and_still_validate(self):
        """现网文件多为 MD5：跳过 File 后必须修剪 CONTAINS，否则硬校验失败。"""
        linx_sbom = _minimal_linx_sbom()
        linx_sbom["files_sbom"] = {"files": [{
            "id": "File-demo",
            "name": "demo.py",
            "path": "src/demo.py",
            "checksums": {
                "algorithm": "MD5",
                "value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
        }]}
        linx_sbom["file_relationships_sbom"] = {"file_relationships": [{
            "id": "Package-demo-abc123",
            "related_element": "File-demo",
            "relationship_type": "CONTAINS",
        }]}

        document = spdx_sbom_helper.convert_to_spdx_document(
            linx_sbom, "demo", "2026-06-16T00:00:00Z", "rpm",
            spdx_version="SPDX-2.3")
        self.assertEqual(document.files, [])
        self.assertFalse(any(
            "File-demo" in (
                relationship.spdx_element_id
                + relationship.related_spdx_element_id)
            for relationship in document.relationships
        ))
        self.assertEqual(
            validate_full_spdx_document(document, "SPDX-2.3"), [])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.json"
            spdx_sbom_helper.write_spdx23(document, str(path))
            self.assertTrue(path.exists())
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload.get("files", []), [])

    def test_write_spdx23_roundtrip_json(self):
        document = spdx_sbom_helper.convert_to_spdx_document(
            _minimal_linx_sbom(),
            "demo",
            "2026-06-16T00:00:00Z",
            "rpm",
            spdx_version="SPDX-2.3",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "spdx-sbom_demo.json"
            spdx_sbom_helper.write_spdx23(document, str(path))
            self.assertTrue(path.exists())
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["spdxVersion"], "SPDX-2.3")


if __name__ == "__main__":
    unittest.main()
