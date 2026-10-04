from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .orchestration import SCAN_GROUPS, resolve_scan_groups
from .reporting.diff import ReportDiffError, compare_report_files, format_diff
from .reporting.pdf import generate_pdf
from .runtime_logging import configure_cli_logging
from .scanner import Scanner
from .version import __version__


logger = logging.getLogger(__name__)


def _parse_group_list(value: str) -> tuple[str, ...]:
    groups = []
    for raw in str(value or "").split(","):
        group = raw.strip().lower()
        if group and group not in groups:
            groups.append(group)

    if not groups:
        raise argparse.ArgumentTypeError("scan group list cannot be empty")

    unknown = [group for group in groups if group not in SCAN_GROUPS]
    if unknown:
        raise argparse.ArgumentTypeError(
            "unknown scan group(s): "
            + ", ".join(unknown)
            + ". Valid groups: "
            + ", ".join(SCAN_GROUPS)
        )
    return tuple(groups)


def _parse_scan_limit(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer between 1 and 100") from exc

    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return parsed


def _resolve_scan_groups(
    scan_groups: tuple[str, ...] | None,
    skip_groups: tuple[str, ...] | None,
) -> tuple[tuple[str, ...], list[str]]:
    """CLI helper delegated to orchestration policy."""
    return resolve_scan_groups(scan_groups, skip_groups)


def _confirm_scan_authorization(domain: str) -> bool:
    """Request authorization confirmation for interactive scan invocations."""
    if not sys.stdin.isatty():
        print(
            "Authorization confirmation is required before scanning. "
            "For non-interactive use, re-run the command with --authorized.",
            file=sys.stderr,
        )
        return False

    print(
        f"This scan will make external requests against {domain}.",
        file=sys.stderr,
    )
    print(
        "Continue only if you own the target or have explicit permission to assess it.",
        file=sys.stderr,
    )
    print("Continue with scan? [y/N]: ", end="", file=sys.stderr, flush=True)

    response = sys.stdin.readline()
    if not response:
        print("", file=sys.stderr)
        print("Scan cancelled.", file=sys.stderr)
        return False

    if response.strip().lower() in {"y", "yes"}:
        return True

    print("Scan cancelled.", file=sys.stderr)
    return False


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "domain",
        help="Domain or subdomain to scan, for example example.com.",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help=(
            "Confirm authorization non-interactively and skip the "
            "authorization prompt."
        ),
    )
    parser.add_argument(
        "--max-pages",
        type=_parse_scan_limit,
        default=20,
        metavar="N",
        help="Maximum pages to crawl (1-100; default: 20).",
    )
    parser.add_argument(
        "--max-hosts",
        type=_parse_scan_limit,
        default=25,
        metavar="N",
        help="Maximum discovered hosts to assess (1-100; default: 25).",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PREFIX",
        help="Output file prefix. Defaults to security-report-<domain>.",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json-only",
        action="store_true",
        help="Write the JSON report without generating a PDF report.",
    )
    output_group.add_argument(
        "--json-stdout",
        action="store_true",
        help=(
            "Write the scanner JSON report to stdout only; "
            "do not create JSON or PDF files."
        ),
    )
    parser.add_argument(
        "--scan",
        type=_parse_group_list,
        metavar="GROUPS",
        help=(
            "Run only the listed comma-separated scan groups. Available: "
            + ", ".join(SCAN_GROUPS)
        ),
    )
    parser.add_argument(
        "--skip",
        type=_parse_group_list,
        metavar="GROUPS",
        help=(
            "Skip the listed comma-separated scan groups. Available: "
            + ", ".join(SCAN_GROUPS)
        ),
    )

    logging_group = parser.add_mutually_exclusive_group()
    logging_group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help=(
            "Increase execution detail. Repeat (-vv) for diagnostic logging."
        ),
    )
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress normal progress and completion output.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Low-impact external domain security hygiene scanner.",
        epilog=(
            "Examples:\n"
            "  domeval scan example.com --authorized\n"
            "  domeval diff previous.json current.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Domain Security Scanner {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an authorized domain.",
        description="Run a security hygiene scan against an authorized domain.",
    )
    _add_scan_arguments(scan_parser)
    scan_parser.set_defaults(handler=run_scan)

    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two existing JSON reports.",
        description="Compare two existing JSON reports without running a scan.",
    )
    diff_parser.add_argument(
        "old_report",
        metavar="OLD_JSON",
        help="Path to the older scanner JSON report.",
    )
    diff_parser.add_argument(
        "new_report",
        metavar="NEW_JSON",
        help="Path to the newer scanner JSON report.",
    )
    diff_parser.set_defaults(handler=run_diff)

    return parser


def run_diff(args: argparse.Namespace) -> int:
    try:
        result = compare_report_files(args.old_report, args.new_report)
    except ReportDiffError as exc:
        print(f"Diff error: {exc}", file=sys.stderr)
        return 2

    print(format_diff(result))
    return 1 if result.has_changes else 0


def run_scan(args: argparse.Namespace) -> int:
    configure_cli_logging(verbose=args.verbose, quiet=args.quiet)

    if not args.authorized and not _confirm_scan_authorization(args.domain):
        return 2

    selected_groups, selection_warnings = _resolve_scan_groups(args.scan, args.skip)
    for warning in selection_warnings:
        logger.warning(f"[!] Warning: {warning}")

    try:
        scanner = Scanner(
            args.domain,
            max_pages=args.max_pages,
            max_hosts=args.max_hosts,
            scan_groups=selected_groups,
        )
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    scanner.set_scan_selection_context(
        requested=args.scan,
        skipped=args.skip,
        warnings_list=selection_warnings,
    )

    skipped_effective = [group for group in SCAN_GROUPS if group not in scanner.scan_groups]

    logger.info(f"[+] Web target: {scanner.target_domain}")
    logger.info(
        "[+] Scan groups: "
        + (", ".join(scanner.scan_groups) if scanner.scan_groups else "(none)")
    )
    logger.info(
        "[+] Skipped groups: "
        + (", ".join(skipped_effective) if skipped_effective else "(none)")
    )
    scanner.run()
    logger.info(f"[+] Root/mail domain: {scanner.root_domain}")
    report = scanner.to_dict()

    report_json = json.dumps(report, ensure_ascii=False, indent=2)
    json_path = None
    pdf_path = None

    if args.json_stdout:
        try:
            stdout_buffer = getattr(sys.stdout, "buffer", None)
            if stdout_buffer is not None:
                stdout_buffer.write((report_json + "\n").encode("utf-8"))
                stdout_buffer.flush()
            else:
                sys.stdout.write(report_json + "\n")
                sys.stdout.flush()
        except BrokenPipeError:
            try:
                sys.stdout.close()
            except (BrokenPipeError, OSError):
                pass
            sys.stdout = None
            return 0
    else:
        prefix = args.out or f"security-report-{scanner.target_domain}"
        json_path = Path(prefix + ".json")
        json_path.write_text(report_json, encoding="utf-8")

        if not args.json_only:
            pdf_path = Path(prefix + ".pdf")
            generate_pdf(report, pdf_path)

    logger.info(f"[+] Score: {report['score']['score']}/100 ({report['score']['label']})")
    if args.json_stdout:
        logger.info("[+] JSON: stdout")
    elif json_path is not None:
        logger.info(f"[+] JSON: {json_path}")
    if pdf_path is not None:
        logger.info(f"[+] PDF:  {pdf_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if (
        args.command == "scan"
        and args.json_stdout
        and args.out is not None
    ):
        parser.error("--json-stdout is stdout-only and cannot be used with --out")

    return args.handler(args)
