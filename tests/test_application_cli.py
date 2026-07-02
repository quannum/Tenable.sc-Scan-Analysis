import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.tenable_coverage_workflow.application_cli import (
    EXIT_APPLY_REQUIRED,
    EXIT_OK,
    main,
)
from tests.test_change_application import FakeDataAccess, approved_row, write_plan


class ApplicationCliTests(unittest.TestCase):
    def test_help_exposes_all_required_commands(self):
        stdout = StringIO()
        with self.assertRaises(SystemExit) as context, redirect_stdout(stdout):
            main(["--help"])

        self.assertEqual(context.exception.code, 0)
        help_text = stdout.getvalue()
        for command in (
            "validate-definitions",
            "collect-tenable",
            "analyze-coverage",
            "propose-changes",
            "apply-changes",
            "export-report",
        ):
            self.assertIn(command, help_text)

    def test_validate_definitions_writes_normalized_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sites.json"
            output = root / "normalized.json"
            source.write_text(
                json.dumps(
                    {"site_code": "LAB01", "private_ranges": ["10.0.0.0/24"]}
                ),
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "validate-definitions",
                    "--source-json-file",
                    str(source),
                    "--output-file",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, EXIT_OK)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["sites"][0]["site_code"], "LAB01")
            self.assertEqual(payload["coverage_targets"][0]["cidr"], "10.0.0.0/24")

    def test_collect_tenable_offline_writes_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scans = root / "scans"
            assets = root / "assets"
            scans.mkdir()
            assets.mkdir()
            (scans / "one.json").write_text(
                json.dumps({"id": 1, "name": "Scan", "ipList": "10.0.0.0/24"}),
                encoding="utf-8",
            )
            output = root / "inventory.json"

            exit_code = main(
                [
                    "collect-tenable",
                    "--scan-json-dir",
                    str(scans),
                    "--asset-json-dir",
                    str(assets),
                    "--output-file",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, EXIT_OK)
            snapshot = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(snapshot["resource_counts"]["scans"], 1)

    def test_apply_changes_requires_explicit_apply(self):
        exit_code = main(["apply-changes", "--plan-file", "plan.json"])
        self.assertEqual(exit_code, EXIT_APPLY_REQUIRED)

    def test_config_cannot_bypass_explicit_apply_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(
                "tenable_sc_scan_analysis:\n"
                "  apply_changes:\n"
                "    apply: true\n"
                "    plan_file: ignored.csv\n",
                encoding="utf-8",
            )
            exit_code = main(
                ["--config-file", str(config), "apply-changes"]
            )
        self.assertEqual(exit_code, EXIT_APPLY_REQUIRED)

    def test_yaml_config_supplies_command_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sites.json"
            output = root / "normalized.json"
            config = root / "config.yaml"
            source.write_text(
                json.dumps({"site_code": "CFG01", "public_ranges": ["192.0.2.0/30"]}),
                encoding="utf-8",
            )
            config.write_text(
                "\n".join(
                    [
                        "tenable_sc_scan_analysis:",
                        f"  source_json_file: '{source.as_posix()}'",
                        "  commands:",
                        "    validate_definitions:",
                        f"      output_file: '{output.as_posix()}'",
                    ]
                ),
                encoding="utf-8",
            )

            exit_code = main(
                ["--config-file", str(config), "validate-definitions"]
            )

            self.assertEqual(exit_code, EXIT_OK)
            self.assertTrue(output.is_file())

    def test_apply_changes_writes_verified_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = write_plan(root / "plan.csv", [approved_row()])
            result_file = root / "result.json"
            data_access = FakeDataAccess()

            with patch(
                "src.tenable_coverage_workflow.application_cli.DataAccess",
                return_value=data_access,
            ):
                exit_code = main(
                    [
                        "apply-changes",
                        "--mode",
                        "live",
                        "--plan-file",
                        str(plan),
                        "--repository-id",
                        "7",
                        "--result-file",
                        str(result_file),
                        "--apply",
                    ]
                )

            self.assertEqual(exit_code, EXIT_OK)
            result = json.loads(result_file.read_text(encoding="utf-8"))
            self.assertEqual(result["status_counts"], {"APPLIED": 1})
            self.assertEqual(len(result["plan_sha256"]), 64)
            self.assertIn(
                "Post-change verification passed",
                result_file.with_suffix(".md").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
