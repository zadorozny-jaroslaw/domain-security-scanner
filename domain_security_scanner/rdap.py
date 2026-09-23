"""Backward-compatible import for the extracted domain scan group."""

from .domains.domain import DomainScanMixin

RdapMixin = DomainScanMixin

__all__ = ["RdapMixin"]
