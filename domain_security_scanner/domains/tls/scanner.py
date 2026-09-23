from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any

from ...constants import TIMEOUT


class TlsScanMixin:
    """HTTPS certificate and TLS protocol checks."""

    def _probe_tls_version(self, version) -> dict[str, Any]:
        label = getattr(version, "name", str(version))
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                try:
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((self.target_domain, 443), timeout=TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                        return {"status": "supported", "protocol": ssock.version(), "cipher": ssock.cipher()[0] if ssock.cipher() else None}
        except ssl.SSLError as e:
            message = str(e).lower()
            if "no ciphers available" in message or "no protocols available" in message:
                return {"status": "unknown", "error": str(e), "label": label}
            return {"status": "not_supported", "error": str(e)}
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            return {"status": "not_supported", "error": str(e)}
        except (OSError, ValueError) as e:
            return {"status": "unknown", "error": str(e), "label": label}

    def check_tls(self):
        host = self.target_domain
        result = {"host": host}
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    cert = s.getpeercert()
                    result["protocol"] = s.version()
                    result["cipher"] = s.cipher()[0] if s.cipher() else None
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["san"] = [x[1] for x in cert.get("subjectAltName", []) if len(x) == 2]
                    result["notAfter"] = cert.get("notAfter")
                    if cert.get("notAfter"):
                        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (expires - datetime.now(timezone.utc)).days
                        result["expiry_days"] = days
                        if days >= 30:
                            self.add_check("Web", "TLS certificate", "pass",
                                           f"Certyfikat poprawny, ważny jeszcze ok. {days} dni.", 6, 6)
                        elif days >= 7:
                            self.add_check("Web", "TLS certificate", "warn",
                                           f"Certyfikat wygasa za ok. {days} dni.", 6, 3)
                        else:
                            self.add_check("Web", "TLS certificate", "fail",
                                           f"Certyfikat wygasa za ok. {days} dni.", 6, 0)
                    else:
                        self.add_check("Web", "TLS certificate", "pass",
                                       "Połączenie TLS zweryfikowane.", 6, 6)
            self.add_check("Web", "HTTPS", "pass",
                           f"HTTPS działa; negocjowany protokół: {result.get('protocol')}.", 8, 8)
        except Exception as e:
            result["error"] = str(e)
            self.add_check("Web", "HTTPS", "fail",
                           f"Nie udało się zweryfikować HTTPS/TLS: {e}", 8, 0)
            self.add_check("Web", "TLS certificate", "fail",
                           "Nie udało się zweryfikować certyfikatu.", 6, 0)

        # Explicit protocol support probes. These are a handful of TLS handshakes,
        # not cipher-suite enumeration.
        support: dict[str, Any] = {}
        versions = []
        for label, attr in (("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"), ("TLS 1.2", "TLSv1_2"), ("TLS 1.3", "TLSv1_3")):
            version = getattr(ssl.TLSVersion, attr, None)
            if version is not None:
                support[label] = self._probe_tls_version(version)
        result["protocol_support"] = support

        legacy_states = [support.get("TLS 1.0", {}).get("status"), support.get("TLS 1.1", {}).get("status")]
        enabled = [label for label in ("TLS 1.0", "TLS 1.1") if support.get(label, {}).get("status") == "supported"]
        unknown = [label for label in ("TLS 1.0", "TLS 1.1") if support.get(label, {}).get("status") == "unknown"]
        if enabled:
            self.add_check("Web", "Legacy TLS", "warn",
                           "Serwer akceptuje starsze protokoły: " + ", ".join(enabled) + ".", 4, 0)
        elif unknown:
            self.add_check("Web", "Legacy TLS", "unknown",
                           "Nie udało się jednoznacznie sprawdzić: " + ", ".join(unknown) + ".", 4, 0, False)
        else:
            self.add_check("Web", "Legacy TLS", "pass",
                           "TLS 1.0 i TLS 1.1 nie są akceptowane przez serwer.", 4, 4)

        self.tls = result
