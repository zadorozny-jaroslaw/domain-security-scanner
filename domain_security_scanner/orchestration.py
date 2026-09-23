from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable


SCAN_GROUPS = ("domain", "discovery", "mail", "tls", "web", "cms")


@dataclass(frozen=True)
class ScanStep:
    """One concrete orchestration step with an owning scan group."""

    active_group: str
    method_name: str
    kwargs: tuple[tuple[str, object], ...] = ()

    def call_kwargs(self) -> dict[str, object]:
        return dict(self.kwargs)


@dataclass(frozen=True)
class _ExecutionRule:
    """Declarative rule used to build an execution plan for selected groups."""

    active_group: str
    method_name: str
    required_any: frozenset[str]
    kwargs_factory: Callable[[frozenset[str]], dict[str, object]] | None = None

    def applies(self, selected: frozenset[str]) -> bool:
        return bool(self.required_any & selected)

    def to_step(self, selected: frozenset[str]) -> ScanStep:
        kwargs = self.kwargs_factory(selected) if self.kwargs_factory else {}
        return ScanStep(
            active_group=self.active_group,
            method_name=self.method_name,
            kwargs=tuple(kwargs.items()),
        )


def _http_context_kwargs(selected: frozenset[str]) -> dict[str, object]:
    return {"run_web_checks": "web" in selected}


# Execution order intentionally preserves the behavior that existed before scan-group
# selection was introduced. `required_any` also makes prerequisite context explicit:
# RDAP/root context is shared by domain/discovery/mail, while the HTTPS homepage is
# shared by web/cms and runs only once when both are selected.
_EXECUTION_RULES = (
    _ExecutionRule(
        active_group="domain",
        method_name="rdap_lookup",
        required_any=frozenset({"domain", "discovery", "mail"}),
    ),
    _ExecutionRule(
        active_group="domain",
        method_name="collect_domain_dns",
        required_any=frozenset({"domain"}),
    ),
    _ExecutionRule(
        active_group="mail",
        method_name="collect_mail_dns",
        required_any=frozenset({"mail"}),
    ),
    _ExecutionRule(
        active_group="discovery",
        method_name="discover_ct_subdomains",
        required_any=frozenset({"discovery"}),
    ),
    _ExecutionRule(
        active_group="discovery",
        method_name="crawl",
        required_any=frozenset({"discovery"}),
    ),
    _ExecutionRule(
        active_group="discovery",
        method_name="collect_subdomain_dns",
        required_any=frozenset({"discovery"}),
    ),
    _ExecutionRule(
        active_group="tls",
        method_name="check_tls",
        required_any=frozenset({"tls"}),
    ),
    _ExecutionRule(
        active_group="web",
        method_name="check_http",
        required_any=frozenset({"web", "cms"}),
        kwargs_factory=_http_context_kwargs,
    ),
    _ExecutionRule(
        active_group="cms",
        method_name="check_cms_currency",
        required_any=frozenset({"cms"}),
    ),
)


def normalize_scan_groups(scan_groups: Iterable[str] | str | None) -> tuple[str, ...]:
    """Validate and return selected groups in canonical public order."""
    if scan_groups is None:
        requested = SCAN_GROUPS
    elif isinstance(scan_groups, str):
        requested = (scan_groups,)
    else:
        requested = tuple(scan_groups)

    unknown = sorted(set(requested) - set(SCAN_GROUPS))
    if unknown:
        raise ValueError(
            "Unknown scan group(s): "
            + ", ".join(unknown)
            + ". Valid groups: "
            + ", ".join(SCAN_GROUPS)
        )

    requested_set = set(requested)
    return tuple(group for group in SCAN_GROUPS if group in requested_set)


def resolve_scan_groups(
    scan_groups: tuple[str, ...] | None,
    skip_groups: tuple[str, ...] | None,
) -> tuple[tuple[str, ...], list[str]]:
    """Apply CLI include/skip semantics; skip always wins."""
    requested = set(SCAN_GROUPS if scan_groups is None else scan_groups)
    skipped = set(skip_groups or ())
    selected = tuple(
        group for group in SCAN_GROUPS
        if group in requested and group not in skipped
    )

    warnings_list: list[str] = []
    if scan_groups is not None and skip_groups is not None:
        warnings_list.append(
            "Both --scan and --skip were provided. --skip has higher priority; "
            "using both options may be redundant."
        )
        overlap = [
            group for group in SCAN_GROUPS
            if group in requested and group in skipped
        ]
        if overlap:
            warnings_list.append(
                "The following scan groups are listed in both --scan and --skip "
                "and will NOT be scanned: " + ", ".join(overlap) + "."
            )

    if not selected:
        warnings_list.append(
            "No scan groups remain selected; the report will contain context only "
            "and no scan findings."
        )

    return selected, warnings_list


def build_scan_selection_context(
    effective: Iterable[str],
    requested: Iterable[str] | None = None,
    skipped: Iterable[str] | None = None,
    warnings_list: Iterable[str] | None = None,
) -> dict[str, object]:
    """Build stable report metadata for the effective and requested scan scope."""
    effective_tuple = normalize_scan_groups(tuple(effective))
    requested_tuple = None if requested is None else tuple(requested)
    skipped_tuple = tuple(skipped or ())
    requested_set = set(SCAN_GROUPS if requested_tuple is None else requested_tuple)
    skipped_set = set(skipped_tuple)
    overlap = [
        group for group in SCAN_GROUPS
        if group in requested_set and group in skipped_set
    ]
    return {
        "requested": None if requested_tuple is None else list(requested_tuple),
        "skipped": [group for group in SCAN_GROUPS if group in skipped_set],
        "overlap": overlap,
        "effective": list(effective_tuple),
        "warnings": list(warnings_list or ()),
    }


def build_scan_plan(scan_groups: Iterable[str] | str | None) -> tuple[ScanStep, ...]:
    """Return the concrete, ordered execution plan for the selected scan groups."""
    selected = frozenset(normalize_scan_groups(scan_groups))
    return tuple(
        rule.to_step(selected)
        for rule in _EXECUTION_RULES
        if rule.applies(selected)
    )


__all__ = [
    "SCAN_GROUPS",
    "ScanStep",
    "normalize_scan_groups",
    "resolve_scan_groups",
    "build_scan_selection_context",
    "build_scan_plan",
]
