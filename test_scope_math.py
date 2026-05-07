import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("tenable-sc-scan-coverage-analysis.py")
SPEC = importlib.util.spec_from_file_location("scan_coverage_analysis", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ScopeMathTests(unittest.TestCase):
    def test_parse_single_ip_as_32(self):
        parsed = MODULE.parse_scope_item("10.0.0.5")
        self.assertEqual(parsed[0], "cidr")
        self.assertEqual(str(parsed[1]), "10.0.0.5/32")

    def test_parse_range_rejects_reverse_order(self):
        with self.assertRaises(ValueError):
            MODULE.parse_scope_item("10.0.0.10-10.0.0.1")

    def test_scope_intersects_when_cidr_is_inside_range(self):
        actual = MODULE.parse_scope_item("10.0.0.0-10.0.0.255")
        expected = MODULE.parse_scope_item("10.0.0.128/25")
        self.assertTrue(MODULE.scope_intersects(actual, expected))

    def test_scope_contains_cidr_contains_range(self):
        actual = MODULE.parse_scope_item("10.0.0.0/24")
        expected = MODULE.parse_scope_item("10.0.0.10-10.0.0.20")
        self.assertTrue(MODULE.scope_contains(actual, expected))

    def test_merge_intervals_merges_adjacent_ranges(self):
        merged = MODULE.merge_intervals([(1, 2), (3, 5), (10, 12)])
        self.assertEqual(merged, [(1, 5), (10, 12)])

    def test_subtract_intervals_splits_range(self):
        remaining = MODULE.subtract_intervals([(1, 10)], [(4, 6)])
        self.assertEqual(remaining, [(1, 3), (7, 10)])

    def test_scope_size_range_is_inclusive(self):
        parsed = MODULE.parse_scope_item("10.0.0.1-10.0.0.3")
        self.assertEqual(MODULE.scope_size(parsed), 3)

    def test_validate_expected_row_rejects_short_rows(self):
        with self.assertRaises(ValueError):
            MODULE.validate_expected_row(("10.0.0.0/24",))


if __name__ == "__main__":
    unittest.main()
