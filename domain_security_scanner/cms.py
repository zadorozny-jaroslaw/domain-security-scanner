"""Backward-compatible import for the extracted CMS scan group."""

from .domains.cms import CmsScanMixin

CmsMixin = CmsScanMixin

__all__ = ["CmsMixin"]
