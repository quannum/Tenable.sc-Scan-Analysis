import unittest
from typing import Any

from src.tenable_coverage_workflow.os_asset_config import (
    build_os_asset_classifications_from_settings,
)
from src.tenable_coverage_workflow.workflow_settings import (
    build_grouping_config_from_settings,
    build_scan_filter_config,
    build_tenable_access_config,
)


class WorkflowSettingsTests(unittest.TestCase):
    @staticmethod
    def _scalar(values: dict[str, Any]):
        return lambda name, _environment_name, default=None: values.get(name, default)

    @staticmethod
    def _csv(values: dict[str, list[str]]):
        return lambda name, _environment_name, default=None: values.get(name, default)

    def test_tenable_access_config_parses_shared_transport_values(self):
        config = build_tenable_access_config(
            self._scalar(
                {
                    "mode": "live",
                    "sc_url": "https://tenable.local",
                    "sc_access_key": "access",
                    "sc_secret_key": "secret",
                    "sc_timeout_seconds": "45",
                    "sc_retries": "4",
                    "sc_backoff_seconds": "2.0",
                    "sc_ssl_verify": "false",
                }
            )
        )

        self.assertEqual(config.mode, "live")
        self.assertEqual(config.sc_timeout_seconds, 45)
        self.assertEqual(config.sc_retries, 4)
        self.assertEqual(config.sc_backoff_seconds, 2.0)
        self.assertFalse(config.sc_ssl_verify)

    def test_tenable_access_config_requires_offline_directories(self):
        with self.assertRaisesRegex(ValueError, "Offline mode requires"):
            build_tenable_access_config(self._scalar({"mode": "offline"}))

    def test_scan_filter_config_uses_shared_validation(self):
        config = build_scan_filter_config(
            self._scalar(
                {
                    "match_all_include": "true",
                    "case_sensitive": "false",
                    "filter_disabled_mode": "ENABLED_ONLY",
                }
            ),
            self._csv(
                {
                    "include_keywords": ["Discovery", "Assessment"],
                    "exclude_keywords": ["Deprecated"],
                }
            ),
        )

        self.assertEqual(config.include_keywords, ["Discovery", "Assessment"])
        self.assertEqual(config.exclude_keywords, ["Deprecated"])
        self.assertTrue(config.match_all_include)
        self.assertFalse(config.case_sensitive)
        self.assertEqual(config.filter_disabled_mode, "ENABLED_ONLY")

    def test_grouping_config_normalizes_keys_and_bucket_values_once(self):
        config = build_grouping_config_from_settings(
            self._scalar(
                {
                    "grouping_mode": "vlan_tag",
                    "grouping_tag_map": {" VLAN-Print ": "network"},
                }
            )
        )

        self.assertEqual(config.tag_map, {"vlan-print": "NETWORK"})

    def test_os_asset_classifications_default_and_custom_mapping(self):
        defaults = build_os_asset_classifications_from_settings(self._scalar({}))
        custom = build_os_asset_classifications_from_settings(
            self._scalar({"os_asset_classifications": {"Unix": "Linux|Unix"}})
        )

        self.assertEqual(
            [(item.name, item.os_contains) for item in defaults],
            [("Windows", "Windows"), ("Linux", "Linux")],
        )
        self.assertEqual(
            [(item.name, item.os_contains) for item in custom],
            [("Unix", "Linux|Unix")],
        )


if __name__ == "__main__":
    unittest.main()
