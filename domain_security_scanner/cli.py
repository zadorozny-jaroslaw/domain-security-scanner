from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .orchestration import SCAN_GROUPS, resolve_scan_groups
from .reporting.pdf import generate_pdf
from .scanner import Scanner
from .version import __version__


def _parse_group_list(value: str) -> tuple[str, ...]:
    groups = []
    for raw in str(value or "").split(","):
        group = raw.strip().lower()
        if group and group not in groups:
            groups.append(group)

    if not groups:
        raise argparse.ArgumentTypeError(
            "scan group list cannot be empty"
        )

    unknown = [group for group in groups if group not in SCAN_GROUPS]
    if unknown:
        raise argparse.ArgumentTypeError(
            "unknown scan group(s): "
            + ", ".join(unknown)
            + ". Valid groups: "
            + ", ".join(SCAN_GROUPS)
        )
    return tuple(groups)


def _resolve_scan_groups(
    scan_groups: tuple[str, ...] | None,
    skip_groups: tuple[str, ...] | None,
) -> tuple[tuple[str, ...], list[str]]:
    """Backward-compatible CLI helper delegated to orchestration policy."""
    return resolve_scan_groups(scan_groups, skip_groups)


def main():
    parser = argparse.ArgumentParser(
        description="Low-impact external domain security hygiene scanner."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Domain Security Scanner {__version__}",
    )
    parser.add_argument("domain", help="Domena, np. example.pl")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Potwierdzam, że mam zgodę na ocenę tej domeny."
    )
    parser.add_argument("--max-pages", type=int, default=20, choices=range(1, 101))
    parser.add_argument("--max-hosts", type=int, default=25, choices=range(1, 101))
    parser.add_argument("--out", default=None, help="Prefiks plików wyjściowych")
    parser.add_argument(
        "--scan",
        type=_parse_group_list,
        metavar="GROUPS",
        help=(
            "Skanuj tylko podane grupy, rozdzielone przecinkami. Dostępne: "
            + ", ".join(SCAN_GROUPS)
        ),
    )
    parser.add_argument(
        "--skip",
        type=_parse_group_list,
        metavar="GROUPS",
        help=(
            "Pomiń podane grupy z pełnego/wybranego skanu, rozdzielone przecinkami. "
            "Dostępne: " + ", ".join(SCAN_GROUPS)
        ),
    )
    args = parser.parse_args()

    if not args.authorized:
        print(
            "Refusing to scan without --authorized. "
            "Run only against domains you own or have explicit permission to assess.",
            file=sys.stderr,
        )
        return 2

    selected_groups, selection_warnings = _resolve_scan_groups(
        args.scan,
        args.skip,
    )
    for warning in selection_warnings:
        print(f"[!] Warning: {warning}", file=sys.stderr)

    try:
        scanner = Scanner(
            args.domain,
            max_pages=args.max_pages,
            max_hosts=args.max_hosts,
            scan_groups=selected_groups,
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    scanner.set_scan_selection_context(
        requested=args.scan,
        skipped=args.skip,
        warnings_list=selection_warnings,
    )

    skipped_effective = [
        group for group in SCAN_GROUPS
        if group not in scanner.scan_groups
    ]

    print(f"[+] Web target: {scanner.target_domain}")
    print(f"[+] Scan groups: {', '.join(scanner.scan_groups) if scanner.scan_groups else '(none)'}")
    print(f"[+] Skipped groups: {', '.join(skipped_effective) if skipped_effective else '(none)'}")
    scanner.run()
    print(f"[+] Root/mail domain: {scanner.root_domain}")
    report = scanner.to_dict()

    prefix = args.out or f"security-report-{scanner.target_domain}"
    json_path = Path(prefix + ".json")
    pdf_path = Path(prefix + ".pdf")

    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    generate_pdf(report, pdf_path)

    print(f"[+] Score: {report['score']['score']}/100 ({report['score']['label']})")
    print(f"[+] JSON: {json_path}")
    print(f"[+] PDF:  {pdf_path}")
    return 0
