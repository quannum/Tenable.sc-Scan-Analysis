import unittest
from io import StringIO
from unittest.mock import patch

import app_config


class AppConfigTests(unittest.TestCase):
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

    def test_no_expected_scope_conflicts_with_expected_scope_file(self):
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            app_config.build_config(
                ["--expected-scope-file", "expected.xlsx", "--no-expected-scope"]
            )


if __name__ == "__main__":
    unittest.main()
