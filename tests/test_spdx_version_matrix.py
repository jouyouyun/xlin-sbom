import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT_DIR = Path(__file__).resolve().parents[1]


def load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "linx_xiling_cli_matrix", ROOT_DIR / "linx-xiling.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class SpdxVersionMatrixTests(unittest.TestCase):
    def setUp(self):
        self.cli = load_cli_module()

    def test_save_sbom_writes_linx_spdx22_spdx_spdx3(self):
        linx_sbom = _minimal_linx_sbom()
        with tempfile.TemporaryDirectory() as tmpdir:
            self.cli.save_sbom(
                linx_sbom, "rpm", "demo", "20260616000000",
                "2026-06-16T00:00:00Z", tmpdir,
                ["linx", "spdx22", "spdx", "spdx3"])
            output_dir = Path(tmpdir) / "demo"
            self.assertTrue(any(output_dir.glob("linx-sbom_*")))
            self.assertTrue(
                (output_dir / "spdx22-sbom_demo_20260616000000.json").exists())
            self.assertTrue(
                (output_dir / "spdx-sbom_demo_20260616000000.json").exists())
            self.assertTrue(
                (output_dir / "spdx3-sbom_demo_20260616000000.jsonld").exists())

    def test_spdx_and_spdx23_write_single_spdx_file(self):
        linx_sbom = _minimal_linx_sbom()
        with tempfile.TemporaryDirectory() as tmpdir:
            self.cli.save_sbom(
                linx_sbom, "rpm", "demo", "20260616000000",
                "2026-06-16T00:00:00Z", tmpdir,
                ["spdx", "spdx23"])
            output_dir = Path(tmpdir) / "demo"
            spdx_files = list(output_dir.glob("spdx-sbom_*"))
            self.assertEqual(len(spdx_files), 1)
            self.assertEqual(
                spdx_files[0].name, "spdx-sbom_demo_20260616000000.json")
            self.assertFalse(any(output_dir.glob("spdx22-sbom_*")))
            self.assertFalse(any(output_dir.glob("spdx3-sbom_*")))

    def test_save_sbom_with_sbomdf_mocks_sign(self):
        linx_sbom = _minimal_linx_sbom()
        with tempfile.TemporaryDirectory() as tmpdir, \
                mock.patch.object(
                    self.cli, "convert_to_sbomdf",
                    return_value={"document": {"formatName": "SBOMDF"}}), \
                mock.patch.object(self.cli, "sign_sbomdf") as sign:
            self.cli.save_sbom(
                linx_sbom, "rpm", "demo", "20260616000000",
                "2026-06-16T00:00:00Z", tmpdir,
                ["linx", "spdx22", "spdx", "spdx3", "sbomdf"],
                "PyPI", {}, "package", None)
            output_dir = Path(tmpdir) / "demo"
            self.assertTrue(any(output_dir.glob("linx-sbom_*")))
            self.assertTrue(
                (output_dir / "spdx22-sbom_demo_20260616000000.json").exists())
            self.assertTrue(
                (output_dir / "spdx-sbom_demo_20260616000000.json").exists())
            self.assertTrue(
                (output_dir / "spdx3-sbom_demo_20260616000000.jsonld").exists())
            sbomdf_dir = output_dir / "sbomdf-sbom_demo_20260616000000"
            self.assertTrue(
                (sbomdf_dir / "sbomdf-sbom_demo_20260616000000.SBOMDF.json"
                 ).exists())
            sign.assert_called_once()


if __name__ == "__main__":
    unittest.main()
