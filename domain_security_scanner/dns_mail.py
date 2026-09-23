"""Backward-compatible import for the extracted mail scan group."""

from .domains.mail import MailScanMixin

DnsMailMixin = MailScanMixin

__all__ = ["DnsMailMixin"]
