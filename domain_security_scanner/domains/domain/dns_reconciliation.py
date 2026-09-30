from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReconciledDelegationView:
    """Combined parent/child NS view using only already-collected evidence.

    Issue #14 performs the first bounded child-NS probes. Issue #15 may later
    obtain a stronger authoritative apex-NS RRset from the same delegated
    servers. This helper lets reporting/findings reuse that later evidence
    without changing the original collectors or turning uncertain data into a
    positive result.
    """

    child_nameservers: tuple[str, ...]
    consistent: bool | None
    complete: bool
    missing_from_child: tuple[str, ...]
    extra_in_child: tuple[str, ...]
    consistency_source: str
    authority_confirmed_servers: tuple[str, ...]


def _name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _authoritative_apex_views(authoritative_analysis: Any) -> dict[str, tuple[str, ...]]:
    views: dict[str, tuple[str, ...]] = {}
    if authoritative_analysis is None:
        return views
    for server in getattr(authoritative_analysis, "servers", ()) or ():
        name = _name(getattr(server, "name", ""))
        values = tuple(
            sorted(
                {
                    _name(value)
                    for value in (getattr(server, "apex_nameservers", ()) or ())
                    if _name(value)
                }
            )
        )
        if name and values:
            views[name] = values
    return views


def reconcile_delegation(
    delegation_analysis: Any,
    authoritative_analysis: Any = None,
) -> ReconciledDelegationView:
    """Reconcile incomplete issue #14 NS evidence with issue #15 apex-NS data.

    Existing conclusive issue #14 results always win. A later authoritative view
    is used only when the original parent/child result is unknown *and* every
    delegated NS has a non-empty authoritative apex NS RRset and those RRsets
    agree with one another. This preserves the timeout/unknown safety model.
    """
    if delegation_analysis is None:
        return ReconciledDelegationView((), None, False, (), (), "unavailable", ())

    parent = tuple(
        sorted(
            {
                _name(value)
                for value in (getattr(delegation_analysis, "parent_nameservers", ()) or ())
                if _name(value)
            }
        )
    )
    child = tuple(
        sorted(
            {
                _name(value)
                for value in (getattr(delegation_analysis, "observed_child_nameservers", ()) or ())
                if _name(value)
            }
        )
    )
    consistent = getattr(delegation_analysis, "parent_child_consistent", None)
    complete = bool(getattr(delegation_analysis, "parent_child_complete", False))
    missing = tuple(getattr(delegation_analysis, "missing_from_child", ()) or ())
    extra = tuple(getattr(delegation_analysis, "extra_in_child", ()) or ())
    source = "delegation_probe"

    views = _authoritative_apex_views(authoritative_analysis)
    expected_servers = tuple(
        _name(getattr(item, "name", ""))
        for item in (getattr(delegation_analysis, "nameservers", ()) or ())
        if _name(getattr(item, "name", ""))
    )
    confirmed = tuple(sorted(name for name in expected_servers if name in views))

    if consistent is None and parent and expected_servers:
        complete_views = all(name in views for name in expected_servers)
        rrsets = {views[name] for name in expected_servers if name in views}
        if complete_views and len(rrsets) == 1:
            child = next(iter(rrsets))
            parent_set = set(parent)
            child_set = set(child)
            consistent = parent_set == child_set
            complete = True
            missing = tuple(sorted(parent_set - child_set))
            extra = tuple(sorted(child_set - parent_set))
            source = "authoritative_apex_ns"

    return ReconciledDelegationView(
        child_nameservers=child,
        consistent=consistent,
        complete=complete,
        missing_from_child=tuple(missing),
        extra_in_child=tuple(extra),
        consistency_source=source,
        authority_confirmed_servers=confirmed,
    )


__all__ = ["ReconciledDelegationView", "reconcile_delegation"]
