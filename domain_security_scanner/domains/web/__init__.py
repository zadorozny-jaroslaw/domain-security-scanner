"""HTTP and application-edge security scan group."""

from .alt_svc import AltSvcScanMixin
from .linking import LinkHeaderScanMixin
from .scanner import WebScanMixin as _BaseWebScanMixin


class WebScanMixin(AltSvcScanMixin, LinkHeaderScanMixin, _BaseWebScanMixin):
    """Compose core Web checks with additive standards-backed Web features."""


__all__ = ["WebScanMixin"]
