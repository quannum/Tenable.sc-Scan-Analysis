import unittest
from types import SimpleNamespace

from src.core.analysis import filter_scans


def config(**overrides):
    defaults = {
        "include_keywords": [],
        "exclude_keywords": [],
        "match_all_include": False,
        "case_sensitive": False,
        "filter_disabled_mode": "ALL",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class FilterScanTests(unittest.TestCase):
    def test_enabled_only_excludes_disabled_scans(self):
        scans = [
            {"name": "Enabled Scan", "schedule": {"enabled": True}},
            {"name": "Disabled Scan", "schedule": {"enabled": False}},
        ]

        filtered = filter_scans(scans, config(filter_disabled_mode="ENABLED_ONLY"))

        self.assertEqual([scan["name"] for scan in filtered], ["Enabled Scan"])

    def test_disabled_only_includes_disabled_scans(self):
        scans = [
            {"name": "Enabled Scan", "schedule": {"enabled": "true"}},
            {"name": "Disabled Scan", "schedule": {"enabled": "false"}},
        ]

        filtered = filter_scans(scans, config(filter_disabled_mode="DISABLED_ONLY"))

        self.assertEqual([scan["name"] for scan in filtered], ["Disabled Scan"])

    def test_include_keywords_can_match_any_keyword(self):
        scans = [{"name": "Prod Weekly"}, {"name": "Dev Monthly"}]

        filtered = filter_scans(scans, config(include_keywords=["weekly", "daily"]))

        self.assertEqual([scan["name"] for scan in filtered], ["Prod Weekly"])

    def test_match_all_include_requires_every_keyword(self):
        scans = [{"name": "Prod Weekly"}, {"name": "Prod Monthly"}]

        filtered = filter_scans(
            scans,
            config(include_keywords=["prod", "weekly"], match_all_include=True),
        )

        self.assertEqual([scan["name"] for scan in filtered], ["Prod Weekly"])

    def test_exclude_keywords_remove_matching_scans(self):
        scans = [{"name": "Prod Weekly"}, {"name": "Discovery Weekly"}]

        filtered = filter_scans(scans, config(exclude_keywords=["discovery"]))

        self.assertEqual([scan["name"] for scan in filtered], ["Prod Weekly"])

    def test_missing_schedule_enabled_defaults_to_true(self):
        scans = [{"name": "No Schedule Scan"}]

        filtered = filter_scans(scans, config(filter_disabled_mode="ENABLED_ONLY"))

        self.assertEqual([scan["name"] for scan in filtered], ["No Schedule Scan"])

    def test_case_sensitive_filtering_respects_letter_case(self):
        scans = [{"name": "Prod Weekly"}, {"name": "prod weekly"}]

        filtered = filter_scans(
            scans,
            config(include_keywords=["Prod"], case_sensitive=True),
        )

        self.assertEqual([scan["name"] for scan in filtered], ["Prod Weekly"])

    def test_filtering_uses_info_name_when_present(self):
        scans = [
            {"name": "fallback", "info": {"name": "Production Weekly"}},
            {"name": "fallback", "info": {"name": "Discovery Monthly"}},
        ]

        filtered = filter_scans(scans, config(include_keywords=["production"]))

        self.assertEqual(
            [scan["info"]["name"] for scan in filtered], ["Production Weekly"]
        )


if __name__ == "__main__":
    unittest.main()
