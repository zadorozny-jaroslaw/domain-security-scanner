from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)


REPORT_SCAN_GROUPS = ("domain", "discovery", "mail", "tls", "web", "cms")


def _report_scan_scope(report: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Return effective, skipped, and warning metadata for report rendering.

    Older JSON reports predate scan_groups, so they remain backward-compatible
    and render as full scans. An explicitly empty scan_groups list means that no
    functional groups were selected.
    """
    if "scan_groups" not in report:
        selected = REPORT_SCAN_GROUPS
    else:
        selected_set = set(report.get("scan_groups") or ())
        selected = tuple(group for group in REPORT_SCAN_GROUPS if group in selected_set)

    skipped = tuple(group for group in REPORT_SCAN_GROUPS if group not in selected)
    selection = report.get("scan_selection", {}) or {}
    warnings_list = tuple(
        str(item).strip()
        for item in (selection.get("warnings") or ())
        if str(item).strip()
    )
    return selected, skipped, warnings_list


def register_pdf_fonts() -> tuple[str, str]:
    """Register a Unicode TTF font so Polish characters render correctly.

    Uses fonts already installed on the host OS; no font files are distributed.
    Windows normally resolves to Arial, Linux to DejaVu Sans.
    """
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        (windir / "Fonts" / "arial.ttf", windir / "Fonts" / "arialbd.ttf"),
        (windir / "Fonts" / "calibri.ttf", windir / "Fonts" / "calibrib.ttf"),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
         Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
        (Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
         Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf")),
        (Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
         Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf")),
        (Path("/Library/Fonts/Arial.ttf"), Path("/Library/Fonts/Arial Bold.ttf")),
    ]
    for regular, bold in candidates:
        if regular.exists():
            pdfmetrics.registerFont(TTFont("LocalUnicode", str(regular)))
            if bold.exists():
                pdfmetrics.registerFont(TTFont("LocalUnicode-Bold", str(bold)))
            else:
                pdfmetrics.registerFont(TTFont("LocalUnicode-Bold", str(regular)))
            return "LocalUnicode", "LocalUnicode-Bold"
    # Last-resort fallback. PDF still builds, but non-Latin glyph coverage depends
    # on the base font. A warning is emitted for diagnostics.
    print("[!] Unicode TTF font not found; PDF may not render Polish characters correctly.", file=sys.stderr)
    return "Helvetica", "Helvetica-Bold"

def p(text: Any) -> str:
    text = str(text if text is not None else "")
    text = text.replace("—", "-").replace("–", "-").replace("→", "->")
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )

def _status_palette(status: str):
    palettes = {
        "fail": (colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B"), colors.HexColor("#DC2626")),
        "warn": (colors.HexColor("#FEF3C7"), colors.HexColor("#92400E"), colors.HexColor("#D97706")),
        "pass": (colors.HexColor("#DCFCE7"), colors.HexColor("#166534"), colors.HexColor("#16A34A")),
        "info": (colors.HexColor("#DBEAFE"), colors.HexColor("#1E40AF"), colors.HexColor("#2563EB")),
        "unknown": (colors.HexColor("#F3F4F6"), colors.HexColor("#4B5563"), colors.HexColor("#6B7280")),
    }
    return palettes.get(status, palettes["unknown"])

def _score_palette(score: int):
    if score >= 90:
        return colors.HexColor("#DCFCE7"), colors.HexColor("#166534"), "Strong"
    if score >= 75:
        return colors.HexColor("#ECFDF5"), colors.HexColor("#047857"), "Good"
    if score >= 60:
        return colors.HexColor("#FEF3C7"), colors.HexColor("#92400E"), "Needs improvement"
    return colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B"), "Priority remediation"

def _host_inventory_groups(report: dict[str, Any]) -> dict[str, list[str]]:
    """Return host groups for reporting, with a fallback for older JSON reports."""
    inventory = report.get("host_inventory")
    keys = ("live", "historical", "unresolved", "dns_unknown", "not_assessed")
    if isinstance(inventory, dict):
        return {key: sorted(set(inventory.get(key, []) or [])) for key in keys}

    # Backward-compatible fallback: old reports do not contain enough evidence to
    # call an empty hostname historical, so place it in the neutral unresolved group.
    dns_records = report.get("dns_records", {}) or {}
    discovered = set(report.get("subdomains", []) or [])
    live = sorted(
        host for host, records in dns_records.items()
        if any(values for values in (records or {}).values())
    )
    unresolved = sorted(
        host for host, records in dns_records.items()
        if not any(values for values in (records or {}).values())
    )
    not_assessed = sorted(discovered - set(dns_records))
    return {
        "live": live,
        "historical": [],
        "unresolved": unresolved,
        "dns_unknown": [],
        "not_assessed": not_assessed,
    }

def _recommendation(check: dict[str, Any]) -> str:
    name = str(check.get("name", "")).lower()
    status = str(check.get("status", "unknown"))
    if status == "pass":
        return "No action required."
    mapping = [
        ("spf duplicate", "Publish exactly one SPF record for the domain."),
        ("spf dns lookup", "Reduce nested include/a/mx/exists/redirect lookups so worst-case SPF evaluation stays below the 10-query limit."),
        ("spf syntax", "Correct the SPF syntax, then re-test the record."),
        ("dmarc syntax", "Correct the DMARC record syntax and keep a single valid policy record."),
        ("dmarc", "Publish/strengthen DMARC and move toward quarantine/reject after validation."),
        ("spf", "Review authorized mail senders and publish a valid SPF policy."),
        ("dkim", "Confirm the mail provider's DKIM selector and enable DKIM signing if needed."),
        ("dnssec", "Enable DNSSEC at the DNS provider/registrar and verify the DS delegation."),
        ("transfer lock", "Enable registrar/registry transfer protection where available."),
        ("domain expiry", "Renew the domain and consider auto-renewal with a monitored payment method."),
        ("caa", "Publish CAA records for the certificate authorities you actually use."),
        ("mta-sts", "Consider MTA-STS after confirming the mail flow and MX configuration."),
        ("tls-rpt", "Add TLS-RPT reporting if mail transport monitoring is desired."),
        ("hsts", "Enable HSTS after confirming HTTPS works correctly across the site."),
        ("csp", "Deploy a tested Content-Security-Policy appropriate for the application."),
        ("x-content-type", "Send X-Content-Type-Options: nosniff."),
        ("frame protection", "Add CSP frame-ancestors or X-Frame-Options where appropriate."),
        ("referrer", "Set a suitable Referrer-Policy."),
        ("permissions", "Set a Permissions-Policy that disables browser capabilities not required by the site."),
        ("http -> https", "Redirect all HTTP traffic to HTTPS."),
        ("https", "Repair HTTPS/TLS configuration and certificate validation."),
        ("tls certificate", "Renew/replace the TLS certificate and verify the full chain."),
        ("rdap", "Verify registrar and registration details manually if automated RDAP lookup is unavailable."),
        ("cookie security", "Set Secure and HttpOnly on session/authentication cookies and choose an appropriate SameSite policy."),
        ("mixed content", "Replace http:// asset/form references with HTTPS or remove them."),
        ("legacy tls", "Disable TLS 1.0/1.1 and retain modern TLS versions supported by your clients."),
        ("server version disclosure", "Remove unnecessary detailed software versions from Server/X-Powered-By style response headers."),
        ("name server", "Use redundant authoritative DNS servers/providers as appropriate."),
    ]
    for needle, action in mapping:
        if needle in name:
            return action
    if status == "fail":
        return "Review and remediate this finding as a priority."
    if status == "warn":
        return "Review the configuration and apply the recommended hardening where appropriate."
    return "Verify manually; the external scan could not determine this reliably."

def _impact(check: dict[str, Any]) -> str:
    """Short, customer-facing explanation of why a WARN/FAIL matters.

    The wording intentionally describes exposure/risk without claiming that
    exploitation or compromise has occurred.
    """
    name = str(check.get("name", "")).lower()
    message = str(check.get("message", "")).lower()

    mapping = [
        ("spf duplicate", "Multiple SPF records can cause SPF PermError, reducing the reliability of anti-spoofing checks."),
        ("spf dns lookup", "SPF evaluation is limited to 10 DNS-querying terms; exceeding it can produce PermError and weaken mail authentication."),
        ("spf syntax", "Invalid SPF syntax can cause receivers to treat the policy as an error instead of authenticating expected senders."),
        ("dmarc syntax", "An invalid or ambiguous DMARC record can prevent receivers from applying your intended anti-spoofing policy."),
        ("dmarc", "Weak or missing DMARC can make it easier for attackers to impersonate your domain in phishing emails."),
        ("spf", "A missing or overly permissive SPF policy can make forged email claiming to come from your domain harder for receivers to reject."),
        ("dkim", "Without confirmed DKIM signing, recipients have less cryptographic assurance that a message genuinely came from your mail system and was not altered in transit."),
        ("dnssec", "Without DNSSEC, DNS answers are not cryptographically validated, reducing protection against forged or tampered DNS responses."),
        ("transfer lock", "Without strong transfer protection, a compromised registrar account may have fewer barriers against unauthorized domain transfer."),
        ("domain expiry", "An expired domain can interrupt the website and email and, if lost, may allow another party to register it."),
        ("caa", "CAA limits which certificate authorities may issue certificates for your domain. Without it, you have less control over certificate issuance policy."),
        ("mta-sts", "Without MTA-STS, mail servers have less protection against downgrade or interception of SMTP transport where both sides support the mechanism."),
        ("tls-rpt", "Without TLS-RPT, failures in secure mail transport are harder to observe and investigate."),
        ("hsts", "Without HSTS, a user's first connection can be more exposed to HTTPS downgrade or SSL-stripping scenarios on hostile networks."),
        ("csp", "A strong Content-Security-Policy can reduce the impact of cross-site scripting and injected third-party content. Without it, the browser has fewer restrictions on what may execute."),
        ("x-content-type", "Without nosniff, some browsers may try to interpret a resource as a different content type, increasing exposure to content-type confusion attacks."),
        ("frame protection", "Without frame restrictions, the site may be embedded in another page and can be more exposed to clickjacking-style attacks."),
        ("referrer", "Without an explicit Referrer-Policy, URLs or path information may be shared with third-party sites more broadly than intended."),
        ("permissions", "Without Permissions-Policy, browser capabilities such as camera, microphone, geolocation or other features are not explicitly restricted by this header."),
        ("http -> https", "If HTTP is not consistently redirected to HTTPS, users can reach an unencrypted entry point and become more exposed to interception or downgrade."),
        ("https", "Broken HTTPS can prevent users from establishing an authenticated, encrypted connection to the site."),
        ("tls certificate", "An invalid or expiring certificate can cause browser warnings or outages and undermine trust in the encrypted connection."),
        ("name server", "Insufficient DNS redundancy can make the domain more dependent on a single DNS failure."),
        ("cms update", "Running an older CMS release may leave known bug fixes and security hardening unapplied. An update should be reviewed and tested before deployment."),
        ("cookie security", "Missing cookie protections can make session or authentication cookies easier to expose through insecure transport or client-side script compromise."),
        ("mixed content", "HTTP resources inside an HTTPS page can be blocked, observed, or modified in transit and weaken the page's transport-security posture."),
        ("legacy tls", "TLS 1.0/1.1 are obsolete protocols with weaker security properties and broader compatibility with legacy cryptography."),
        ("server version disclosure", "Exact software versions give attackers additional fingerprinting information that can help prioritize version-specific attacks."),
        ("application response", "A server-side error can make the website unavailable and may indicate a failed upstream service, reverse proxy, or application dependency."),
    ]

    for key, value in mapping:
        if key in name:
            return value

    # Message-aware fallback for CMS currency checks.
    if "update available" in message or "latest" in message and "detected" in message:
        return "An older CMS release may be missing bug fixes and security hardening available in the current maintained release."

    status = str(check.get("status", "")).lower()
    if status == "fail":
        return "This finding can materially affect availability, confidentiality, integrity, or trust and should be reviewed promptly."
    if status == "warn":
        return "This is a hardening gap or configuration weakness that can increase exposure in some attack scenarios."
    return ""

def _technical_status(label: str, value: Any, report: dict[str, Any]) -> str:
    """Map Web/TLS detail rows to a display status."""
    key = label.lower()
    http = report.get("http", {}) or {}
    tls = report.get("tls", {}) or {}
    cms = http.get("cms", {}) or {}
    currency = cms.get("currency", {}) or {}

    if key == "cms / platform":
        return "info" if cms.get("detected") else "unknown"

    if key in ("cms latest stable", "cms update status"):
        state = str(currency.get("status") or "").lower()
        if state in ("current", "current_branch"):
            return "pass"
        if state in ("update_available", "update available"):
            return "warn"
        return "unknown"

    if key == "tls protocol":
        proto = str(tls.get("protocol") or "").upper()
        if proto in ("TLSV1.3", "TLSV1.2", "TLS1.3", "TLS1.2"):
            return "pass"
        if proto:
            return "warn"
        return "unknown"

    if key == "tls cipher":
        return "pass" if tls.get("cipher") else "unknown"

    if key == "certificate expires in":
        days = tls.get("expiry_days")
        if isinstance(days, int):
            if days < 7:
                return "fail"
            if days < 30:
                return "warn"
            return "pass"
        return "unknown"

    if key == "https final url":
        return "info"

    if key == "https status":
        status = http.get("https_status")
        try:
            status = int(status)
        except (TypeError, ValueError):
            return "unknown"
        if 200 <= status < 400:
            return "pass"
        if 400 <= status < 500:
            return "warn"
        if status >= 500:
            return "fail"
        return "unknown"

    if key == "security.txt":
        return "pass" if http.get("security_txt") else "info"

    if key == "cms evidence":
        return "info" if cms.get("signals") else "unknown"

    if key in ("tls 1.0", "tls 1.1"):
        # Exact dictionary keys are title case (TLS 1.0 / TLS 1.1).
        lookup_label = "TLS 1.0" if key == "tls 1.0" else "TLS 1.1"
        state = (tls.get("protocol_support", {}).get(lookup_label, {}) or {}).get("status")
        if state == "supported":
            return "warn"
        if state == "not_supported":
            return "pass"
        return "unknown"

    if key == "mixed content":
        return "warn" if http.get("mixed_content") else "pass"

    if key == "cookie security flags":
        cookies = http.get("cookies", {}) or {}
        if cookies.get("warning_count", 0):
            return "warn"
        if cookies.get("sensitive_count", 0):
            return "pass"
        return "info"

    if key == "server/version disclosure":
        disclosure = http.get("server_disclosure", {}) or {}
        if disclosure.get("exact_version"):
            return "warn"
        return "info" if disclosure.get("headers") else "pass"

    return "info"

def generate_pdf(report: dict[str, Any], output: Path):
    regular_font, bold_font = register_pdf_fonts()
    styles = getSampleStyleSheet()
    for style_name in ("Title", "Heading1", "Heading2", "Heading3", "BodyText", "Normal"):
        if style_name in styles:
            styles[style_name].fontName = regular_font
    styles["Title"].fontName = bold_font
    styles["Heading1"].fontName = bold_font
    styles["Heading2"].fontName = bold_font
    styles["Heading3"].fontName = bold_font
    styles.add(ParagraphStyle(
        name="CenterTitle",
        parent=styles["Title"],
        fontName=bold_font,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155"),
    ))
    styles.add(ParagraphStyle(
        name="Tiny",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#475569"),
    ))
    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        fontName=bold_font,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6,
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.setLineWidth(0.4)
        canvas.line(14*mm, 10*mm, A4[0]-14*mm, 10*mm)
        canvas.setFont(regular_font, 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(14*mm, 6.5*mm, "© 2026 Jarosław Zadorożny | External Security Hygiene Report")
        canvas.drawRightString(A4[0]-14*mm, 6.5*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=14*mm, leftMargin=14*mm,
        topMargin=14*mm, bottomMargin=16*mm,
        title=f"External Security Hygiene - {report['target_domain']}",
        author="Jarosław Zadorożny",
        subject="External Security Hygiene Report",
    )
    story = []

    score = report["score"]
    score_value = int(score["score"])
    score_bg, score_fg, score_label = _score_palette(score_value)
    checks = report.get("checks", [])
    counts = {s: sum(1 for c in checks if c.get("status") == s) for s in ("fail", "warn", "pass", "info", "unknown")}
    selected_scan_groups, skipped_scan_groups, selection_warnings = _report_scan_scope(report)
    selected_scan_group_set = set(selected_scan_groups)
    scan_selection = report.get("scan_selection", {}) or {}

    story.append(Paragraph("External Security Hygiene Report", styles["CenterTitle"]))
    story.append(Paragraph(f"<b>{p(report['target_domain'])}</b>", ParagraphStyle(
        "Target", parent=styles["Heading2"], fontName=bold_font, alignment=TA_CENTER,
        textColor=colors.HexColor("#1E293B"), spaceAfter=8
    )))

    # Score banner + customer-friendly status counters.
    score_box = Table([
        [Paragraph(f"<b>{score_value}/100</b><br/><font size='9'>{p(score_label)}</font>", ParagraphStyle(
            "Score", parent=styles["BodyText"], fontName=bold_font, alignment=TA_CENTER,
            textColor=score_fg, fontSize=22, leading=24
        ))]
    ], colWidths=[58*mm], rowHeights=[28*mm])
    score_box.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), score_bg),
        ("BOX", (0,0), (-1,-1), 1.2, score_fg),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]))

    counter_cells = []
    for status, label in (("fail", "ACTION"), ("warn", "REVIEW"), ("pass", "OK"), ("unknown", "VERIFY")):
        bg, fg, border = _status_palette(status)
        cell = Table([[Paragraph(
            f"<b>{counts[status]}</b><br/><font size='7'>{label}</font>",
            ParagraphStyle(f"Counter-{status}", parent=styles["Small"], fontName=bold_font,
                           alignment=TA_CENTER, textColor=fg, fontSize=14, leading=15)
        )]], colWidths=[27*mm], rowHeights=[13*mm])
        cell.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), bg),
            ("BOX", (0,0), (-1,-1), 0.8, border),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        counter_cells.append(cell)

    counters = Table([counter_cells[:2], counter_cells[2:]], colWidths=[29*mm,29*mm], rowHeights=[14*mm,14*mm])
    counters.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "MIDDLE")]))

    overview = Table([[score_box, counters]], colWidths=[64*mm, 62*mm], hAlign="CENTER")
    overview.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 2),
        ("RIGHTPADDING", (0,0), (-1,-1), 2),
    ]))
    story.append(overview)
    story.append(Spacer(1, 8))

    meta = Table([
        ["Web host", report.get("target_domain", "n/a"), "Root / mail domain", report.get("root_domain", "n/a")],
        ["Generated", report.get("generated_at", "n/a"), "Assessment type", "External / low-impact"],
    ], colWidths=[25*mm, 62*mm, 30*mm, 61*mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (2,0), (2,-1), colors.HexColor("#F1F5F9")),
        ("FONTNAME", (0,0), (-1,-1), regular_font),
        ("FONTNAME", (0,0), (0,-1), bold_font),
        ("FONTNAME", (2,0), (2,-1), bold_font),
        ("FONTSIZE", (0,0), (-1,-1), 7.5),
        ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor("#334155")),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(meta)
    story.append(Spacer(1, 6))

    scope_rows = [
        ["Scanned groups", ", ".join(selected_scan_groups) or "(none)"],
        ["Skipped groups", ", ".join(skipped_scan_groups) or "(none)"],
    ]
    requested_scan = scan_selection.get("requested")
    requested_skip = scan_selection.get("skipped") or []
    if requested_scan is not None:
        scope_rows.append(["Requested --scan", ", ".join(requested_scan) or "(none)"])
    if requested_skip:
        scope_rows.append(["Requested --skip", ", ".join(requested_skip)])

    scope_table = Table([
        [Paragraph(f"<b>{p(label)}</b>", styles["Small"]), Paragraph(p(value), styles["Small"])]
        for label, value in scope_rows
    ], colWidths=[40*mm, 138*mm])
    scope_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#F8FAFC")),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTNAME", (0,0), (-1,-1), regular_font),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(Paragraph("Scan scope", styles["Heading3"]))
    story.append(scope_table)

    if selection_warnings:
        warning_rows = [
            [Paragraph(f"<b>Selection warning:</b> {p(warning)}", styles["Small"])]
            for warning in selection_warnings
        ]
        warning_table = Table(warning_rows, colWidths=[178*mm])
        warning_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#FEF3C7")),
            ("BOX", (0,0), (-1,-1), 0.6, colors.HexColor("#D97706")),
            ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor("#92400E")),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(Spacer(1, 5))
        story.append(warning_table)

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>How to read this report:</b> red findings should be reviewed first, amber findings are recommended improvements, "
        "green findings passed the external check, and grey findings require manual verification. "
        "This is a security-hygiene snapshot, not a penetration test or guarantee of security.",
        styles["Small"]
    ))

    # Customer-focused priority summary.
    priorities = [c for c in checks if c.get("status") in ("fail", "warn")]
    order = {"fail": 0, "warn": 1}
    priorities = sorted(priorities, key=lambda x: (order.get(x.get("status"), 9), x.get("category", ""), x.get("name", "")))[:6]
    story.append(Paragraph("Top priorities", styles["Section"]))
    if priorities:
        pr_rows = [["Status", "Issue", "Finding / why it matters", "Recommended action"]]
        for c in priorities:
            pr_rows.append([
                c["status"].upper(),
                Paragraph(f"<b>{p(c['name'])}</b><br/><font size='7'>{p(c.get('category',''))}</font>", styles["Small"]),
                Paragraph(
                    f"<b>Finding:</b> {p(c['message'])}<br/><b>Why it matters:</b> {p(_impact(c))}",
                    styles["Small"]
                ),
                Paragraph(p(_recommendation(c)), styles["Small"]),
            ])
        pr_table = Table(pr_rows, colWidths=[18*mm, 34*mm, 64*mm, 62*mm], repeatRows=1)
        pr_style = [
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), bold_font),
            ("FONTNAME", (0,1), (-1,-1), regular_font),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]
        for idx, c in enumerate(priorities, start=1):
            bg, fg, border = _status_palette(c["status"])
            pr_style += [
                ("BACKGROUND", (0,idx), (0,idx), bg),
                ("TEXTCOLOR", (0,idx), (0,idx), fg),
                ("FONTNAME", (0,idx), (0,idx), bold_font),
                ("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFFBEB") if c["status"] == "warn" else colors.HexColor("#FFF7F7")),
            ]
        pr_table.setStyle(TableStyle(pr_style))
        story.append(pr_table)
    else:
        story.append(Paragraph("No red or amber findings were detected in the external checks.", styles["Small"]))

    # Full findings table with colored status and subtle row background.
    story.append(Paragraph("All findings", styles["Section"]))
    rows = [["Status", "Area", "Check", "Result"]]
    sort_order = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "pass": 4}
    sorted_checks = sorted(checks, key=lambda x: (sort_order.get(x["status"], 9), x["category"], x["name"]))
    for c in sorted_checks:
        result_text = p(c["message"])
        if c.get("status") in ("fail", "warn"):
            impact = _impact(c)
            if impact:
                result_text += f"<br/><font size='7'><b>Why it matters:</b> {p(impact)}</font>"
        rows.append([
            c["status"].upper(), c["category"], c["name"], Paragraph(result_text, styles["Small"])
        ])
    table = Table(rows, colWidths=[20*mm, 24*mm, 38*mm, 94*mm], repeatRows=1)
    table_style = [
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), bold_font),
        ("FONTNAME", (0,1), (-1,-1), regular_font),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#CBD5E1")),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]
    for idx, c in enumerate(sorted_checks, start=1):
        bg, fg, border = _status_palette(c["status"])
        table_style += [
            ("BACKGROUND", (0,idx), (0,idx), bg),
            ("TEXTCOLOR", (0,idx), (0,idx), fg),
            ("FONTNAME", (0,idx), (0,idx), bold_font),
        ]
        if c["status"] == "pass":
            table_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#F8FFF9")))
        elif c["status"] == "fail":
            table_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFF9F9")))
        elif c["status"] == "warn":
            table_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFFCF5")))
    table.setStyle(TableStyle(table_style))
    story.append(table)

    # Scope-aware technical detail sections.
    if "domain" in selected_scan_group_set:
        story.append(Paragraph("Domain / RDAP", styles["Section"]))
        rdap = report.get("rdap", {})
        domain_rows = [
            ["Web host", report.get("target_domain", report.get("domain"))],
            ["Registered/root domain", report.get("root_domain", "n/a")],
            ["RDAP source", rdap.get("url", "n/a")],
            ["Registrar", rdap.get("registrar", "n/a")],
            ["Nameservers", ", ".join(rdap.get("nameservers", [])) or "n/a"],
            ["Statuses", ", ".join(rdap.get("status", [])) or "n/a"],
            ["Transfer lock", rdap.get("transfer_lock", "unknown")],
            ["NASK state", rdap.get("nask0_state", "n/a")],
        ]
        t = Table([
            [Paragraph(f"<b>{p(a)}</b>", styles["Small"]), Paragraph(p(b), styles["Small"])]
            for a, b in domain_rows
        ], colWidths=[40*mm, 138*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F8FAFC")),
            ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("FONTNAME",(0,0),(-1,-1),regular_font),
        ]))
        story.append(t)

    if "mail" in selected_scan_group_set:
        story.append(Paragraph(f"Mail security - {p(report.get('root_domain', ''))}", styles["Section"]))
        mail = report.get("mail", {})
        spf_analysis = mail.get("spf_analysis", {}) or {}
        spf_dns = spf_analysis.get("dns_lookups", {}) or {}
        dmarc_analysis = mail.get("dmarc_analysis", {}) or {}
        mail_rows = [
            ["MX", "<br/>".join(p(x) for x in mail.get("mx", [])) or "n/a"],
            ["SPF", "<br/>".join(p(x) for x in mail.get("spf", [])) or "not detected"],
            ["SPF record count", spf_analysis.get("record_count", "n/a")],
            ["SPF syntax", "valid" if (spf_analysis.get("syntax", {}) or {}).get("valid") else ("invalid" if spf_analysis.get("syntax") else "n/a")],
            ["SPF DNS lookup estimate", f"{spf_dns.get('count')}/10" if spf_dns.get("count") is not None else "n/a"],
            ["DMARC", "<br/>".join(p(x) for x in mail.get("dmarc", [])) or "not detected"],
            ["DMARC policy", p(mail.get("dmarc_policy", "n/a"))],
            ["DMARC subdomain policy", dmarc_analysis.get("subdomain_policy", "n/a")],
            ["DMARC pct", dmarc_analysis.get("pct", "n/a")],
            ["DMARC aggregate reports (rua)", ", ".join(dmarc_analysis.get("rua", [])) or "not configured"],
            ["DMARC alignment", f"DKIM={dmarc_analysis.get('adkim','n/a')} / SPF={dmarc_analysis.get('aspf','n/a')}"],
            ["DKIM selectors found", ", ".join(mail.get("dkim_common_selectors", {}).keys()) or "not confirmed"],
            ["MTA-STS", "detected" if mail.get("mta_sts_dns") or mail.get("mta_sts_policy") else "not detected"],
            ["TLS-RPT", "<br/>".join(p(x) for x in mail.get("tls_rpt", [])) or "not detected"],
        ]
        t = Table([
            [Paragraph(f"<b>{p(a)}</b>", styles["Small"]), Paragraph(str(b), styles["Small"])]
            for a, b in mail_rows
        ], colWidths=[40*mm, 138*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F8FAFC")),
            ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("FONTNAME",(0,0),(-1,-1),regular_font),
        ]))
        story.append(t)

    selected_web_detail_groups = [
        ("web", "Web"),
        ("tls", "TLS"),
        ("cms", "CMS"),
    ]
    selected_web_detail_labels = [
        label for group, label in selected_web_detail_groups
        if group in selected_scan_group_set
    ]

    if selected_web_detail_labels:
        tls = report.get("tls", {})
        http = report.get("http", {})
        cms = http.get("cms", {}) or {}
        cms_name = cms.get("name") or "not reliably detected"
        cms_version = cms.get("version") or "not disclosed"
        cms_confidence = cms.get("confidence") or "none"
        cms_display = f"{cms_name} | version: {cms_version} | confidence: {cms_confidence}"
        currency = cms.get("currency", {}) or {}
        latest_display = currency.get("latest_same_major") or currency.get("latest_version") or "not checked"
        currency_status = str(currency.get("status") or "not checked").replace("_", " ")

        web_rows = []
        if "cms" in selected_scan_group_set:
            web_rows.extend([
                ["CMS / platform", cms_display],
                ["CMS latest stable", latest_display],
                ["CMS update status", currency_status],
                ["CMS evidence", "; ".join(cms.get("signals", [])[:5]) or "n/a"],
            ])
        if "tls" in selected_scan_group_set:
            web_rows.extend([
                ["TLS protocol", tls.get("protocol", "n/a")],
                ["TLS cipher", tls.get("cipher", "n/a")],
                ["TLS 1.0", (tls.get("protocol_support", {}).get("TLS 1.0", {}) or {}).get("status", "not checked")],
                ["TLS 1.1", (tls.get("protocol_support", {}).get("TLS 1.1", {}) or {}).get("status", "not checked")],
                ["Certificate expires in", f"{tls.get('expiry_days')} days" if tls.get("expiry_days") is not None else "n/a"],
            ])
        if "web" in selected_scan_group_set:
            web_rows.extend([
                ["HTTPS final URL", http.get("final_url", "n/a")],
                ["HTTPS status", http.get("https_status", "n/a")],
                ["Mixed content", f"{len(http.get('mixed_content', []))} insecure reference(s)" if http.get("mixed_content") else "none detected"],
                ["Cookie security flags", f"{(http.get('cookies', {}) or {}).get('sensitive_count', 0)} sensitive / {(http.get('cookies', {}) or {}).get('warning_count', 0)} warning(s)"],
                ["Server/version disclosure", ", ".join(f"{k}: {v}" for k, v in (http.get("server_disclosure", {}).get("headers", {}) or {}).items()) or "none detected"],
                ["security.txt", "yes" if http.get("security_txt") else "no / unknown"],
            ])

        story.append(Paragraph(" / ".join(selected_web_detail_labels), styles["Section"]))
        web_detail_rows = [["Status", "Item", "Value"]]
        web_detail_statuses = []
        for label, value in web_rows:
            display_status = _technical_status(label, value, report)
            web_detail_statuses.append(display_status)
            status_label = {
                "pass": "OK",
                "warn": "REVIEW",
                "fail": "ACTION",
                "info": "INFO",
                "unknown": "VERIFY",
            }.get(display_status, display_status.upper())
            web_detail_rows.append([
                status_label,
                Paragraph(f"<b>{p(label)}</b>", styles["Small"]),
                Paragraph(p(value), styles["Small"]),
            ])

        t = Table(web_detail_rows, colWidths=[22*mm, 44*mm, 112*mm], repeatRows=1)
        web_style = [
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0F172A")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),bold_font),
            ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("FONTNAME",(0,1),(-1,-1),regular_font),
            ("FONTSIZE",(0,0),(-1,-1),7),
            ("LEFTPADDING",(0,0),(-1,-1),4),
            ("RIGHTPADDING",(0,0),(-1,-1),4),
            ("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]
        for idx, display_status in enumerate(web_detail_statuses, start=1):
            bg, fg, border = _status_palette(display_status)
            web_style += [
                ("BACKGROUND", (0,idx), (0,idx), bg),
                ("TEXTCOLOR", (0,idx), (0,idx), fg),
                ("FONTNAME", (0,idx), (0,idx), bold_font),
                ("BACKGROUND", (1,idx), (1,idx), colors.HexColor("#F8FAFC")),
            ]
            if display_status == "pass":
                web_style.append(("BACKGROUND", (2,idx), (2,idx), colors.HexColor("#F0FDF4")))
            elif display_status == "warn":
                web_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFFBEB")))
            elif display_status == "fail":
                web_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FEF2F2")))
            elif display_status == "unknown":
                web_style.append(("BACKGROUND", (2,idx), (2,idx), colors.HexColor("#F9FAFB")))
        t.setStyle(TableStyle(web_style))
        story.append(t)

    show_inventory = "discovery" in selected_scan_group_set
    show_dns_appendix = bool({"domain", "discovery"} & selected_scan_group_set)
    if show_inventory or show_dns_appendix:
        story.append(PageBreak())

    inventory = None
    if show_inventory:
        story.append(Paragraph("External inventory", styles["Section"]))
        inventory = _host_inventory_groups(report)
        discovered_count = len(report.get("subdomains", []))
        story.append(Paragraph(
            f"<b>Subdomains / hosts discovered:</b> {discovered_count} &nbsp; "
            f"<b>current DNS:</b> {len(inventory['live'])} &nbsp; "
            f"<b>historical:</b> {len(inventory['historical'])}",
            styles["BodyText"]
        ))

        def append_host_group(title: str, hosts: list[str], note: str | None = None):
            if not hosts:
                return
            story.append(Paragraph(title, styles["Heading3"]))
            if note:
                story.append(Paragraph(note, styles["Tiny"]))
            host_rows = [["Host"]] + [[Paragraph(p(host), styles["Small"])] for host in hosts]
            ht = Table(host_rows, colWidths=[178*mm], repeatRows=1)
            ht.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0F172A")),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),bold_font),
                ("FONTNAME",(0,1),(-1,-1),regular_font),
                ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
                ("FONTSIZE",(0,0),(-1,-1),7),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(ht)

        append_host_group(
            f"Current DNS hosts ({len(inventory['live'])})",
            inventory["live"],
            "At least one current record was returned from the low-impact DNS inventory.",
        )
        append_host_group(
            f"Historical CT hostnames ({len(inventory['historical'])})",
            inventory["historical"],
            "Previously observed in Certificate Transparency, but current DNS returned NXDOMAIN. These names are kept as historical evidence and are not shown in the live DNS appendix.",
        )
        append_host_group(
            f"Currently unresolved hostnames ({len(inventory['unresolved'])})",
            inventory["unresolved"],
            "No current A/AAAA/CNAME/MX/TXT/NS/CAA records were returned, but the evidence was not strong enough to classify the name as historical.",
        )
        append_host_group(
            f"DNS status unknown ({len(inventory['dns_unknown'])})",
            inventory["dns_unknown"],
            "One or more DNS queries failed (for example timeout or SERVFAIL), so these names are not classified as inactive or historical.",
        )
        append_host_group(
            f"Discovered but not DNS-assessed ({len(inventory['not_assessed'])})",
            inventory["not_assessed"],
            "These names were discovered after the configured DNS host limit was reached.",
        )

        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<b>Public email addresses discovered on crawled pages:</b> {len(report.get('emails', []))}",
            styles["BodyText"]
        ))
        if report.get("emails"):
            story.append(Paragraph("<br/>".join(p(x) for x in report["emails"]), styles["Small"]))
        else:
            story.append(Paragraph("None found.", styles["Small"]))

    if show_dns_appendix:
        if inventory is None:
            inventory = _host_inventory_groups(report)
        story.append(Paragraph("DNS appendix - current records", styles["Section"]))
        live_hosts = set(inventory["live"])
        dns_records = report.get("dns_records", {}) or {}
        ordered_live_hosts = [host for host in dns_records if host in live_hosts]
        ordered_live_hosts.extend(sorted(live_hosts - set(ordered_live_hosts)))

        if not ordered_live_hosts:
            story.append(Paragraph("No hosts with current DNS records were confirmed.", styles["Small"]))

        for host in ordered_live_hosts:
            records = dns_records.get(host, {}) or {}
            block = [Paragraph(f"<b>{p(host)}</b>", styles["BodyText"])]
            dns_rows = [["Type", "Value"]]
            for rtype, values in records.items():
                if values:
                    dns_rows.append([rtype, Paragraph("<br/>".join(p(v) for v in values), styles["Small"])])
            if len(dns_rows) == 1:
                continue
            dt = Table(dns_rows, colWidths=[22*mm, 156*mm], repeatRows=1)
            dt.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E2E8F0")),
                ("FONTNAME",(0,0),(-1,0),bold_font),
                ("FONTNAME",(0,1),(-1,-1),regular_font),
                ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
                ("FONTSIZE",(0,0),(-1,-1),7)
            ]))
            block += [dt, Spacer(1, 6)]
            story.append(KeepTogether(block))

    story.append(Paragraph("Limitations", styles["Section"]))
    for item in report.get("limitations", []):
        story.append(Paragraph("- " + p(item), styles["Small"]))

    story.append(Spacer(1, 10))
    legal = Table([[Paragraph(
        "<b>Report ownership:</b> © 2026 Jarosław Zadorożny. "
        "The scanner software is licensed for non-commercial use only; see the accompanying LICENSE file. "
        "This report may be shared with the assessed organization for remediation purposes.", styles["Tiny"]
    )]], colWidths=[178*mm])
    legal.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(legal)

    doc.build(story, onFirstPage=footer, onLaterPages=footer)

