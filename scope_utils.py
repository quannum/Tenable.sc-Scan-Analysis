import ipaddress
from typing import Any


ParsedScope = tuple[str, Any]

_parsed_cache = {}


def parse_scope_item(scope):
    """Parse CIDR, IP range, or single-IP text into a comparable scope tuple."""
    scope = str(scope).strip()
    if not scope:
        raise ValueError("Scope item is blank")

    if scope in _parsed_cache:
        return _parsed_cache[scope]

    try:
        if "/" in scope:
            parsed = ("cidr", ipaddress.ip_network(scope, strict=False))
        elif "-" in scope:
            start, end = scope.split("-", maxsplit=1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            if int(start_ip) > int(end_ip):
                raise ValueError(f"Invalid IP range order: '{scope}'")

            parsed = ("range", (start_ip, end_ip))
        else:
            ip = ipaddress.ip_address(scope)
            parsed = ("cidr", ipaddress.ip_network(f"{ip}/32"))
    except ValueError as exc:
        raise ValueError(f"Invalid scope item '{scope}': {exc}") from exc

    _parsed_cache[scope] = parsed
    return parsed


def split_scope_items(scope_string):
    """Split a comma-separated Tenable scope string into individual scope items."""
    return [item.strip() for item in scope_string.split(",") if item.strip()]


def scope_contains(actual, expected):
    """Return True when the actual scan scope fully contains the expected scope."""
    actual_type, actual_value = actual
    expected_type, expected_value = expected

    if actual_type == "cidr" and expected_type == "cidr":
        return expected_value.subnet_of(actual_value)

    if actual_type == "cidr" and expected_type == "range":
        start, end = expected_value
        return start in actual_value and end in actual_value

    if actual_type == "range" and expected_type == "cidr":
        return (
            actual_value[0] <= expected_value.network_address
            and actual_value[1] >= expected_value.broadcast_address
        )

    if actual_type == "range" and expected_type == "range":
        return (
            actual_value[0] <= expected_value[0]
            and actual_value[1] >= expected_value[1]
        )

    return False


def scope_intersects(actual, expected):
    """Return True when two parsed scopes share at least one IP address."""
    actual_start, actual_end = scope_to_interval(actual)
    expected_start, expected_end = scope_to_interval(expected)
    return actual_start <= expected_end and actual_end >= expected_start


def scope_to_interval(parsed):
    """Convert a parsed scope into inclusive integer start and end IP bounds."""
    parsed_type, parsed_value = parsed
    if parsed_type == "cidr":
        return int(parsed_value.network_address), int(parsed_value.broadcast_address)
    return int(parsed_value[0]), int(parsed_value[1])


def merge_intervals(intervals):
    """Merge overlapping or adjacent inclusive integer intervals."""
    if not intervals:
        return []

    sorted_intervals = sorted(intervals)
    merged = [sorted_intervals[0]]

    for start, end in sorted_intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))

    return merged


def subtract_intervals(included, excluded):
    """Subtract excluded intervals from included intervals and return remaining ranges."""
    remaining_intervals = []

    for included_start, included_end in included:
        remaining = [(included_start, included_end)]

        for excluded_start, excluded_end in excluded:
            next_remaining = []

            for remaining_start, remaining_end in remaining:
                if excluded_end < remaining_start or excluded_start > remaining_end:
                    next_remaining.append((remaining_start, remaining_end))
                    continue

                if excluded_start > remaining_start:
                    next_remaining.append((remaining_start, excluded_start - 1))
                if excluded_end < remaining_end:
                    next_remaining.append((excluded_end + 1, remaining_end))

            remaining = next_remaining
            if not remaining:
                break

        remaining_intervals.extend(remaining)

    return remaining_intervals


def scope_size(parsed):
    """Return the inclusive IP count represented by a parsed scope."""
    parsed_type, parsed_value = parsed
    if parsed_type == "cidr":
        return parsed_value.num_addresses
    return int(parsed_value[1]) - int(parsed_value[0]) + 1
