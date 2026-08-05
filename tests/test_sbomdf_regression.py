import unittest
from unittest import mock

from actions.scanner import sbomdf_helper


class SbomdfRegressionTests(unittest.TestCase):
    def test_convert_to_sbomdf_smoke_format_name(self):
        linx_sbom = {
            "packages_sbom": {"packages": [{
                "id": "Package-app-aaa",
                "name": "app",
                "version": "1.0",
                "licenses": ["LicenseRef-mit"],
                "suppliers": [{"name": "App Vendor"}],
                "checksum": {
                    "algorithm": "SHA1",
                    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            }]},
            "licenses_sbom": {"licenses": [
                {"id": "LicenseRef-mit", "name": "MIT"},
            ]},
            "package_relationships_sbom": {"package_relationships": []},
        }
        with mock.patch.object(
                sbomdf_helper,
                "query_sbomdf_vulnerabilities",
                return_value=[]) as query:
            sbomdf = sbomdf_helper.convert_to_sbomdf(
                linx_sbom, "app", "2026-06-16T00:00:00Z",
                "source", "package", "PyPI", {}, None)

        self.assertEqual(sbomdf["document"]["formatName"], "SBOMDF")
        self.assertEqual(sbomdf["document"]["formatVersion"], "1.0")
        self.assertEqual(sbomdf["software"]["softwareName"], "app")
        query.assert_called_once()


if __name__ == "__main__":
    unittest.main()
