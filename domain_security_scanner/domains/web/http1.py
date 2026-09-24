from __future__ import annotations

from ...standards import RFC_9112, analyze_http1_response_framing


class Http1FramingScanMixin:
    """Add passive RFC 9112 response-framing metadata analysis."""

    @staticmethod
    def _response_http_version(response):
        raw = getattr(response, "raw", None)
        version = getattr(raw, "version", None)
        if version is not None:
            return version
        original = getattr(raw, "_original_response", None)
        return getattr(original, "version", None)

    @staticmethod
    def _raw_header_fidelity(response) -> bool:
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        return bool(raw_headers is not None and hasattr(raw_headers, "getlist"))

    def _capture_http1_framing(self, response):
        return analyze_http1_response_framing(
            http_version=self._response_http_version(response),
            status_code=getattr(response, "status_code", 0),
            request_method="GET",
            content_length_values=self._header_values(response, "Content-Length"),
            transfer_encoding_values=self._header_values(response, "Transfer-Encoding"),
            connection_values=self._header_values(response, "Connection"),
            raw_header_fidelity=self._raw_header_fidelity(response),
        )

    def _capture_web_response_metadata(self, response, result):
        """Capture RFC 9112 metadata from the already-fetched primary response."""
        try:
            result["http1_framing"] = self._capture_http1_framing(response)
        except Exception as exc:
            result["http1_framing"] = {
                "observed": False,
                "applicable": False,
                "http_version": None,
                "valid": False,
                "review": False,
                "errors": [],
                "warnings": [],
                "notes": [f"passive framing metadata capture failed: {exc}"],
                "coverage": "parsed response metadata only",
                "raw_wire_checked": False,
                "body_length_verified": False,
                "chunk_boundaries_verified": False,
                "trailers_verified": False,
            }

    def check_http(self, run_web_checks: bool = True):
        result = super().check_http(run_web_checks=run_web_checks)
        if not run_web_checks:
            return result

        http = getattr(self, "http", {}) or {}
        analysis = http.get("http1_framing")
        if not analysis:
            return result

        review_items = analysis.get("errors", []) + analysis.get("warnings", [])
        if review_items:
            self.add_check(
                "Web",
                "HTTP/1.1 framing metadata",
                "warn",
                f"Metadane ramek HTTP wymagają przeglądu wg {RFC_9112.label}: "
                + "; ".join(review_items[:3])
                + ". Sprawdzenie jest pasywne i nie analizuje surowych bajtów odpowiedzi.",
                0,
                0,
                False,
            )
        elif analysis.get("applicable"):
            self.add_check(
                "Web",
                "HTTP/1.1 framing metadata",
                "info",
                f"Obserwowalne metadane ramek HTTP/1.1 są spójne z {RFC_9112.label} "
                f"(framing: {analysis.get('framing')}). "
                "To częściowe sprawdzenie pasywne; surowa składnia, granice chunków i długość ciała nie są weryfikowane.",
                0,
                0,
                False,
            )
        else:
            version = analysis.get("http_version")
            version_text = f"HTTP/{version}" if version else "nieustalona wersja HTTP"
            self.add_check(
                "Web",
                "HTTP/1.1 framing metadata",
                "info",
                f"{version_text}; pełna ocena {RFC_9112.label} nie ma zastosowania "
                "lub wersja protokołu nie jest dostępna przez klienta HTTP. "
                "Nie wykonano dodatkowego żądania ani surowego probe.",
                0,
                0,
                False,
            )

        return result


__all__ = ["Http1FramingScanMixin"]
