import unittest

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


class Spdx22OutputTests(unittest.TestCase):
    def test_convert_to_spdx_document_spdx22_validates(self):
        document = spdx_sbom_helper.convert_to_spdx_document(
            _minimal_linx_sbom(),
            "demo",
            "2026-06-16T00:00:00Z",
            "rpm",
            spdx_version="SPDX-2.2",
        )
        self.assertEqual(document.creation_info.spdx_version, "SPDX-2.2")
        self.assertIsNone(document.packages[0].primary_package_purpose)
        self.assertEqual(
            validate_full_spdx_document(document, "SPDX-2.2"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
