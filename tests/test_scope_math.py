import unittest

from tenable_scan_analysis.core.analysis import validate_expected_row
from tenable_scan_analysis.core.scope_utils import (
    merge_intervals,
    parse_scope_item,
    scope_contains,
    scope_intersects,
    scope_size,
    subtract_intervals,
)


class ScopeMathTests(unittest.TestCase):
    def test_parse_single_ip_as_32(self):
        parsed = parse_scope_item("10.0.0.5")
        self.assertEqual(parsed[0], "cidr")
        self.assertEqual(str(parsed[1]), "10.0.0.5/32")

    def test_parse_range_rejects_reverse_order(self):
        with self.assertRaises(ValueError):
            parse_scope_item("10.0.0.10-10.0.0.1")

    def test_parse_scope_rejects_ipv6(self):
        with self.assertRaisesRegex(ValueError, "IPv6 is not supported"):
            parse_scope_item("2001:db8::/32")

    def test_scope_intersects_when_cidr_is_inside_range(self):
        actual = parse_scope_item("10.0.0.0-10.0.0.255")
        expected = parse_scope_item("10.0.0.128/25")
        self.assertTrue(scope_intersects(actual, expected))

    def test_scope_contains_cidr_contains_range(self):
        actual = parse_scope_item("10.0.0.0/24")
        expected = parse_scope_item("10.0.0.10-10.0.0.20")
        self.assertTrue(scope_contains(actual, expected))

    def test_merge_intervals_merges_adjacent_ranges(self):
        merged = merge_intervals([(1, 2), (3, 5), (10, 12)])
        self.assertEqual(merged, [(1, 5), (10, 12)])

    def test_subtract_intervals_splits_range(self):
        remaining = subtract_intervals([(1, 10)], [(4, 6)])
        self.assertEqual(remaining, [(1, 3), (7, 10)])

    def test_scope_size_range_is_inclusive(self):
        parsed = parse_scope_item("10.0.0.1-10.0.0.3")
        self.assertEqual(scope_size(parsed), 3)

    def test_validate_expected_row_rejects_short_rows(self):
        with self.assertRaises(ValueError):
            validate_expected_row(("10.0.0.0/24",))


if __name__ == "__main__":
    unittest.main()
