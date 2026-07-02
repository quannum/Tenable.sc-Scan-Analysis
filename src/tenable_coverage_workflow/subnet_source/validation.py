import ipaddress

from ..models import CoverageTarget, SourceLoadResult, ValidationIssue


def add_relationship_issues(result: SourceLoadResult) -> SourceLoadResult:
    """Add deterministic duplicate and overlap findings across valid targets."""
    targets = result.coverage_targets
    for target in targets:
        network = ipaddress.ip_network(target.cidr, strict=False)
        if target.target_type == "PUBLIC" and network.is_private:
            result.validation_issues.append(
                ValidationIssue(
                    source_file=target.source_file or "authoritative-source",
                    site_code=target.site_code,
                    field_name="public_ranges",
                    severity="WARNING",
                    message=(
                        f"Public range {target.cidr} is classified as non-public "
                        "by Python ipaddress. Verify the source classification."
                    ),
                )
            )
        elif target.target_type in {"PRIVATE_SUPERNET", "VLAN"} and not (
            network.is_private
        ):
            result.validation_issues.append(
                ValidationIssue(
                    source_file=target.source_file or "authoritative-source",
                    site_code=target.site_code,
                    field_name="private_ranges",
                    severity="WARNING",
                    message=(
                        f"Private/VLAN range {target.cidr} is not classified as "
                        "private by Python ipaddress. Verify the source classification."
                    ),
                )
            )
    seen_duplicates: set[tuple[str, str, str, str]] = set()
    for left_index, left in enumerate(targets):
        left_network = ipaddress.ip_network(left.cidr, strict=False)
        for right in targets[left_index + 1 :]:
            right_network = ipaddress.ip_network(right.cidr, strict=False)
            if left_network.version != right_network.version:
                continue
            if left_network == right_network:
                key = tuple(
                    sorted(
                        (
                            _target_identity(left),
                            _target_identity(right),
                        )
                    )
                ) + (str(left_network), left.target_type)
                if key in seen_duplicates:
                    continue
                seen_duplicates.add(key)
                result.validation_issues.append(
                    _relationship_issue(
                        left,
                        right,
                        "Duplicate authoritative range",
                        severity="ERROR",
                    )
                )
            elif left_network.overlaps(right_network):
                # Parent private networks are expected to contain their own VLANs.
                if _is_expected_parent_child(left, right):
                    continue
                result.validation_issues.append(
                    _relationship_issue(
                        left,
                        right,
                        "Overlapping authoritative ranges",
                        severity="WARNING",
                    )
                )
    return result


def _relationship_issue(
    left: CoverageTarget,
    right: CoverageTarget,
    label: str,
    severity: str,
) -> ValidationIssue:
    return ValidationIssue(
        source_file=left.source_file or "authoritative-source",
        site_code=left.site_code,
        field_name="network_ranges",
        severity=severity,
        message=(
            f"{label}: {left.site_code}/{left.target_type} {left.cidr} and "
            f"{right.site_code}/{right.target_type} {right.cidr} "
            f"({right.source_file or 'authoritative-source'})."
        ),
    )


def _is_expected_parent_child(
    left: CoverageTarget, right: CoverageTarget
) -> bool:
    if left.site_code != right.site_code:
        return False
    return {left.target_type, right.target_type} == {"PRIVATE_SUPERNET", "VLAN"}


def _target_identity(target: CoverageTarget) -> str:
    return "|".join(
        (
            target.source_file or "",
            target.site_code,
            target.target_type,
            target.vlan_name or "",
        )
    )
