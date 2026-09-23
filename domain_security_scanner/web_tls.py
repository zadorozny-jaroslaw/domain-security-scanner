"""Backward-compatible imports for the extracted web and TLS scan groups."""

from .domains.tls import TlsScanMixin
from .domains.web import WebScanMixin


class WebTlsMixin(TlsScanMixin, WebScanMixin):
    """Backward-compatible combined web and TLS mixin."""


__all__ = ["WebScanMixin", "WebTlsMixin"]
