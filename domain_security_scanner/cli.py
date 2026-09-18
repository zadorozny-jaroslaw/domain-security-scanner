from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .reporting.pdf import generate_pdf
from .scanner import Scanner
from .version import __version__


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
    args = parser.parse_args()

    if not args.authorized:
        print(
            "Refusing to scan without --authorized. "
            "Run only against domains you own or have explicit permission to assess.",
            file=sys.stderr,
        )
        return 2

    try:
        scanner = Scanner(args.domain, max_pages=args.max_pages, max_hosts=args.max_hosts)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    print(f"[+] Web target: {scanner.target_domain}")
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
