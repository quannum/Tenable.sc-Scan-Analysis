import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.tenable_coverage_workflow.application_cli import (
    EXIT_APPLY_REQUIRED,
    EXIT_OK,
    EXIT_OPERATION,
    main,
)
from tests.test_change_application import FakeDataAccess, approved_row, write_plan


class ApplicationCliTests(unittest.TestCase):
    def _subnet_module(self, site_code: str, scope: str):
        class Module:
            @staticmethod
            def get_sites(**kwargs):
                return {
                    "site_definition": [
                        {
                            "site_code": site_code,
                            "site_name": site_code,
                            "private_ranges": [scope],
                        }
                    ]
                }

        return Module

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

    def test_analyze_help_exposes_scan_filtering_options(self):
        stdout = StringIO()
        with self.assertRaises(SystemExit) as context, redirect_stdout(stdout):
            main(["analyze-coverage", "--help"])

        self.assertEqual(context.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("--include-keywords", help_text)
        self.assertIn("--exclude-keywords", help_text)
        self.assertIn("--filter-disabled-mode", help_text)

    def test_validate_definitions_writes_normalized_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "normalized.json"

            with patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "importlib.import_module",
                return_value=self._subnet_module("LAB01", "10.0.0.0/24"),
            ):
                exit_code = main(
                    [
                        "validate-definitions",
                        "--subnet-as-code-method",
                        "get_sites",
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

    def test_collect_tenable_accepts_live_credentials_and_tcw_env(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "inventory.json"
            env = {
                "TCW_SC_ACCESS_KEY": "tcw-access",
                "SC_ACCESS_KEY": "legacy-access",
                "TCW_SC_TIMEOUT_SECONDS": "45",
                "SC_TIMEOUT_SECONDS": "60",
            }

            with (
                patch.dict(os.environ, env, clear=False),
                patch(
                    "src.tenable_coverage_workflow.application_cli.DataAccess"
                ) as data_access_cls,
                patch(
                    "src.tenable_coverage_workflow.application_cli."
                    "collect_tenable_inventory",
                    return_value={"schema_version": 1, "collection_errors": {}},
                ),
            ):
                exit_code = main(
                    [
                        "collect-tenable",
                        "--mode",
                        "live",
                        "--sc-url",
                        "https://tenable.local",
                        "--sc-secret-key",
                        "cli-secret",
                        "--output-file",
                        str(output),
                    ]
                )

            self.assertEqual(exit_code, EXIT_OK)
            config_arg = data_access_cls.call_args.args[0]
            self.assertEqual(config_arg.sc_url, "https://tenable.local")
            self.assertEqual(config_arg.sc_access_key, "tcw-access")
            self.assertEqual(config_arg.sc_secret_key, "cli-secret")
            self.assertEqual(config_arg.sc_timeout_seconds, 45)

    def test_config_rejects_invalid_mode_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.yaml"
            config.write_text(
                "\n".join(
                    [
                        "tenable_sc_scan_analysis:",
                        '  mode: "livet"',
                        "  commands:",
                        "    collect_tenable:",
                        f"      output_file: '{(root / 'inventory.json').as_posix()}'",
                    ]
                ),
                encoding="utf-8",
            )

            with patch(
                "src.tenable_coverage_workflow.application_cli.DataAccess"
            ) as data_access_cls:
                exit_code = main(["--config-file", str(config), "collect-tenable"])

            self.assertEqual(exit_code, EXIT_OPERATION)
            data_access_cls.assert_not_called()

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
            exit_code = main(["--config-file", str(config), "apply-changes"])
        self.assertEqual(exit_code, EXIT_APPLY_REQUIRED)

    def test_yaml_config_supplies_command_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "normalized.json"
            config = root / "config.yaml"
            config.write_text(
                "\n".join(
                    [
                        "tenable_sc_scan_analysis:",
                        "  subnet_as_code_method: get_sites",
                        "  commands:",
                        "    validate_definitions:",
                        f"      output_file: '{output.as_posix()}'",
                    ]
                ),
                encoding="utf-8",
            )

            with patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "importlib.import_module",
                return_value=self._subnet_module("CFG01", "192.0.2.0/30"),
            ):
                exit_code = main(["--config-file", str(config), "validate-definitions"])

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

    def test_analyze_coverage_config_can_set_vlan_tag_grouping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scans = root / "scans"
            assets = root / "assets"
            scans.mkdir()
            assets.mkdir()
            config = root / "config.yaml"
            config.write_text(
                "\n".join(
                    [
                        "tenable_sc_scan_analysis:",
                        "  subnet_as_code_method: get_sites",
                        '  grouping_mode: "vlan_tag"',
                        '  grouping_vlan_tag_prefix: "vlan-"',
                        "  grouping_tag_map:",
                        '    vlan-workstation: "END_USER"',
                        "  commands:",
                        "    analyze_coverage:",
                        f"      output_dir: '{(root / 'output').as_posix()}'",
                        '      mode: "offline"',
                        f"      scan_json_dir: '{scans.as_posix()}'",
                        f"      asset_json_dir: '{assets.as_posix()}'",
                    ]
                ),
                encoding="utf-8",
            )

            with patch(
                "src.tenable_coverage_workflow.application_cli.run_detect_and_plan",
                return_value={
                    "run_id": "run-001",
                    "output_directory": str(root / "output"),
                },
            ) as run_mock:
                exit_code = main(["--config-file", str(config), "analyze-coverage"])

            self.assertEqual(exit_code, EXIT_OK)
            config_arg = run_mock.call_args.args[0]
            self.assertEqual(config_arg.grouping_config.mode, "vlan_tag")
            self.assertEqual(config_arg.grouping_config.vlan_tag_prefix, "vlan-")
            self.assertEqual(
                config_arg.grouping_config.tag_map,
                {"vlan-workstation": "END_USER"},
            )

    def test_analyze_coverage_config_can_set_scan_filtering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scans = root / "scans"
            assets = root / "assets"
            scans.mkdir()
            assets.mkdir()
            config = root / "config.yaml"
            config.write_text(
                "\n".join(
                    [
                        "tenable_sc_scan_analysis:",
                        "  subnet_as_code_method: get_sites",
                        "  commands:",
                        "    analyze_coverage:",
                        f"      output_dir: '{(root / 'output').as_posix()}'",
                        '      mode: "offline"',
                        f"      scan_json_dir: '{scans.as_posix()}'",
                        f"      asset_json_dir: '{assets.as_posix()}'",
                        '      include_keywords: "Weekly,Production"',
                        '      exclude_keywords: "Deprecated"',
                        "      match_all_include: true",
                        "      case_sensitive: true",
                        '      filter_disabled_mode: "ENABLED_ONLY"',
                    ]
                ),
                encoding="utf-8",
            )

            with patch(
                "src.tenable_coverage_workflow.application_cli.run_detect_and_plan",
                return_value={
                    "run_id": "run-001",
                    "output_directory": str(root / "output"),
                },
            ) as run_mock:
                exit_code = main(["--config-file", str(config), "analyze-coverage"])

            self.assertEqual(exit_code, EXIT_OK)
            config_arg = run_mock.call_args.args[0]
            self.assertEqual(config_arg.include_keywords, ["Weekly", "Production"])
            self.assertEqual(config_arg.exclude_keywords, ["Deprecated"])
            self.assertTrue(config_arg.match_all_include)
            self.assertTrue(config_arg.case_sensitive)
            self.assertEqual(config_arg.filter_disabled_mode, "ENABLED_ONLY")

    def test_analyze_coverage_rejects_invalid_grouping_mode_from_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scans = root / "scans"
            assets = root / "assets"
            scans.mkdir()
            assets.mkdir()
            config = root / "config.yaml"
            config.write_text(
                "\n".join(
                    [
                        "tenable_sc_scan_analysis:",
                        "  subnet_as_code_method: get_sites",
                        '  grouping_mode: "by_magic"',
                        "  commands:",
                        "    analyze_coverage:",
                        f"      output_dir: '{(root / 'output').as_posix()}'",
                        '      mode: "offline"',
                        f"      scan_json_dir: '{scans.as_posix()}'",
                        f"      asset_json_dir: '{assets.as_posix()}'",
                    ]
                ),
                encoding="utf-8",
            )

            stdout = StringIO()
            with (
                patch(
                    "src.tenable_coverage_workflow.application_cli.run_detect_and_plan"
                ) as run_mock,
                redirect_stdout(stdout),
            ):
                exit_code = main(["--config-file", str(config), "analyze-coverage"])

            self.assertEqual(exit_code, EXIT_OPERATION)
            self.assertIn("grouping_mode", stdout.getvalue())
            run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
