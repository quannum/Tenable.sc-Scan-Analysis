import unittest
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import tenable_scan_analysis.io.app_config as app_config
from tenable_scan_analysis.constants import VERSION, default_output_file


class AppConfigTests(unittest.TestCase):
    def test_default_output_file_includes_date_and_time(self):
        output_file = default_output_file(datetime(2026, 5, 7, 13, 2, 3))
        self.assertEqual(
            str(output_file),
            str(Path("output") / "tenable_scan_summary-20260507-130203.xlsx"),
        )

    def test_live_mode_with_no_expected_scope_does_not_prompt(self):
        with patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs:
            config = app_config.build_config(["--mode", "live", "--no-expected-scope"])

        prompt_for_inputs.assert_not_called()
        self.assertEqual(config.mode, "live")
        self.assertIsNone(config.expected_scope_file)
        self.assertIsNone(config.scan_json_dir)
        self.assertIsNone(config.asset_json_dir)

    def test_missing_offline_paths_prompt_when_interactive(self):
        with (
            patch("tenable_scan_analysis.io.app_config.os.makedirs"),
            patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs,
        ):
            prompt_for_inputs.return_value = ("picked-scans", "picked-assets", "")
            config = app_config.build_config(["--no-expected-scope"])

        prompt_for_inputs.assert_called_once_with(
            ask_scan_dir=True,
            ask_asset_dir=True,
            ask_expected_file=False,
        )
        self.assertEqual(config.scan_json_dir, "picked-scans")
        self.assertEqual(config.asset_json_dir, "picked-assets")

    def test_non_interactive_missing_paths_fails_without_prompt(self):
        with (
            patch("sys.stderr", new=StringIO()),
            patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs,
            self.assertRaises(SystemExit),
        ):
            app_config.build_config(["--non-interactive", "--no-expected-scope"])

        prompt_for_inputs.assert_not_called()

    def test_non_interactive_requires_expected_scope_choice(self):
        with (
            patch("sys.stderr", new=StringIO()),
            patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs,
            self.assertRaises(SystemExit),
        ):
            app_config.build_config(
                [
                    "--non-interactive",
                    "--scan-json-dir",
                    "scans",
                    "--asset-json-dir",
                    "assets",
                ]
            )

        prompt_for_inputs.assert_not_called()

    def test_offline_mode_with_all_paths_does_not_prompt(self):
        with (
            patch("tenable_scan_analysis.io.app_config.os.makedirs") as makedirs,
            patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs,
        ):
            config = app_config.build_config(
                [
                    "--scan-json-dir",
                    "scans",
                    "--asset-json-dir",
                    "assets",
                    "--expected-scope-file",
                    "expected.xlsx",
                ]
            )

        prompt_for_inputs.assert_not_called()
        self.assertEqual(makedirs.call_count, 2)
        self.assertEqual(config.scan_json_dir, "scans")
        self.assertEqual(config.asset_json_dir, "assets")
        self.assertEqual(config.expected_scope_file, "expected.xlsx")
        self.assertIsNone(config.expected_sheet)

    def test_expected_sheet_is_configurable(self):
        with (
            patch("tenable_scan_analysis.io.app_config.os.makedirs"),
            patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs,
        ):
            config = app_config.build_config(
                [
                    "--scan-json-dir",
                    "scans",
                    "--asset-json-dir",
                    "assets",
                    "--expected-scope-file",
                    "expected.xlsx",
                    "--expected-sheet",
                    "CustomSheet",
                ]
            )

        prompt_for_inputs.assert_not_called()
        self.assertEqual(config.expected_sheet, "CustomSheet")

    def test_log_file_is_configurable(self):
        with (
            patch("tenable_scan_analysis.io.app_config.os.makedirs"),
            patch("tenable_scan_analysis.io.app_config.prompt_for_inputs") as prompt_for_inputs,
        ):
            config = app_config.build_config(
                [
                    "--scan-json-dir",
                    "scans",
                    "--asset-json-dir",
                    "assets",
                    "--no-expected-scope",
                    "--log-file",
                    "logs/run.log",
                ]
            )

        prompt_for_inputs.assert_not_called()
        self.assertEqual(config.log_file, Path("logs/run.log"))

    def test_version_flag_reports_version(self):
        with patch("sys.stdout", new=StringIO()) as stdout, self.assertRaises(SystemExit):
            app_config.build_config(["--version"])

        self.assertIn(VERSION, stdout.getvalue())

    def test_no_expected_scope_conflicts_with_expected_scope_file(self):
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            app_config.build_config(
                ["--expected-scope-file", "expected.xlsx", "--no-expected-scope"]
            )


if __name__ == "__main__":
    unittest.main()
