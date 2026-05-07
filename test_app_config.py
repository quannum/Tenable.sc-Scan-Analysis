import unittest
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import app_config
from constants import VERSION, default_output_file


class AppConfigTests(unittest.TestCase):
    def test_default_output_file_includes_date_and_time(self):
        output_file = default_output_file(datetime(2026, 5, 7, 13, 2, 3))
        self.assertEqual(
            str(output_file),
            str(Path("output") / "tenable_scan_summary-20260507-130203.xlsx"),
        )

    def test_live_mode_with_no_expected_scope_does_not_prompt(self):
        with patch("app_config.prompt_for_inputs") as prompt_for_inputs:
            config = app_config.build_config(["--mode", "live", "--no-expected-scope"])

        prompt_for_inputs.assert_not_called()
        self.assertEqual(config.mode, "live")
        self.assertIsNone(config.expected_scope_file)
        self.assertIsNone(config.scan_json_dir)
        self.assertIsNone(config.asset_json_dir)

    def test_offline_mode_with_all_paths_does_not_prompt(self):
        with (
            patch("app_config.os.makedirs") as makedirs,
            patch("app_config.prompt_for_inputs") as prompt_for_inputs,
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
            patch("app_config.os.makedirs"),
            patch("app_config.prompt_for_inputs") as prompt_for_inputs,
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
