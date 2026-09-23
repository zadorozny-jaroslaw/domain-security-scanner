"""Backward-compatible import for the extracted discovery scan group."""

from .domains.discovery import DiscoveryScanMixin

InventoryMixin = DiscoveryScanMixin

__all__ = ["InventoryMixin"]
