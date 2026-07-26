import ipaddress
from typing import Any

ParsedScope = tuple[str, Any]

_parsed_cache: dict[str, ParsedScope] = {}

# CIDRs, IP ranges, and single addresses are converted to integer intervals
# before coverage calculations. This keeps the comparison rules consistent.


def ensure_ipv4(value, scope):
    """Reject IPv6 scope values

    Examples:
        10.1.0.1 passes
        2001:db8::1 raises a ValueError
    """
    if value.version != 4:
        raise ValueError(f"IPv6 is not supported: '{scope}'")


def parse_scope_item(scope):
    """Parse a CIDR, IP range, or single IPv4 address

    Examples:
        "10.1.0.0/24" becomes a CIDR scope
        "10.1.0.10-10.1.0.20" becomes an IP range
        "10.1.0.5" becomes a single-address /32 scope
    """
    scope = str(scope).strip()
    if not scope:
        raise ValueError("Scope item is blank")

    if scope in _parsed_cache:
        return _parsed_cache[scope]

    try:
        # Keep the original meaning of each input while making it comparable later.
        if "/" in scope:
            network = ipaddress.ip_network(scope, strict=False)
            ensure_ipv4(network, scope)
            parsed = ("cidr", network)
        elif "-" in scope:
            start, end = scope.split("-", maxsplit=1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            ensure_ipv4(start_ip, scope)
            ensure_ipv4(end_ip, scope)
            if int(start_ip) > int(end_ip):
                raise ValueError(f"Invalid IP range order: '{scope}'")

            parsed = ("range", (start_ip, end_ip))
        else:
            ip = ipaddress.ip_address(scope)
            ensure_ipv4(ip, scope)
            parsed = ("cidr", ipaddress.ip_network(f"{ip}/32"))
    except ValueError as exc:
        raise ValueError(f"Invalid scope item '{scope}': {exc}") from exc

    _parsed_cache[scope] = parsed
    return parsed


def split_scope_items(scope_string):
    """Split a comma-separated scope string

    Example:
        "10.1.0.0/24, 10.1.1.0/24" becomes two scope strings
    """
    return [item.strip() for item in scope_string.split(",") if item.strip()]


def scope_contains(actual, expected):
    """Check whether one scope fully contains another

    Example:
        10.1.0.0/16 contains 10.1.16.0/24
    """
    actual_start, actual_end = scope_to_interval(actual)
    expected_start, expected_end = scope_to_interval(expected)
    return actual_start <= expected_start and actual_end >= expected_end


def scope_intersects(actual, expected):
    """Check whether two scopes share any addresses

    Example:
        10.1.0.0/24 intersects 10.1.0.128/25
    """
    actual_start, actual_end = scope_to_interval(actual)
    expected_start, expected_end = scope_to_interval(expected)
    return actual_start <= expected_end and actual_end >= expected_start


def scope_to_interval(parsed):
    """Convert a parsed scope to inclusive integer bounds

    Example:
        10.1.0.0/24 becomes (167837696, 167837951)
    """
    parsed_type, parsed_value = parsed
    if parsed_type == "cidr":
        return int(parsed_value.network_address), int(parsed_value.broadcast_address)
    return int(parsed_value[0]), int(parsed_value[1])


def merge_intervals(intervals):
    """Merge overlapping or adjacent integer ranges

    Example:
        [(10, 20), (21, 30), (40, 50)] becomes [(10, 30), (40, 50)]
    """
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
    """Remove excluded address ranges from included address ranges

    Example:
        Included 10.1.0.0 through 10.1.0.255
        Excluded 10.1.0.100 through 10.1.0.199

        Returns the remaining ranges before and after the exclusion
    """
    remaining_intervals = []

    for included_start, included_end in included:
        remaining = [(included_start, included_end)]

        # One excluded range can split an included range into two smaller ranges.
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
    """Count the addresses in a parsed scope

    Example:
        10.1.0.0/24 has 256 addresses
    """
    parsed_type, parsed_value = parsed
    if parsed_type == "cidr":
        return parsed_value.num_addresses
    return int(parsed_value[1]) - int(parsed_value[0]) + 1
