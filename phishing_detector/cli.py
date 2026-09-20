"""Command-line interface: ``python -m phishing_detector <url> [<url> ...]``."""

from __future__ import annotations

import argparse
import json
import sys

from .detector import analyze

COLORS = {"PHISHING": "\033[91m", "SUSPICIOUS": "\033[93m", "LIKELY SAFE": "\033[92m"}
RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishing_detector", description="Flag likely phishing URLs using heuristics.")
    p.add_argument("urls", nargs="*", help="URLs to analyze")
    p.add_argument("-f", "--file", help="text file with one URL per line")
    p.add_argument("--whois", action="store_true", help="look up domain age (needs python-whois + network)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    if not urls:
        print("No URLs given. Try: python -m phishing_detector http://example.com", file=sys.stderr)
        return 2

    results = [analyze(u, check_whois=args.whois) for u in urls]

    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
        return 0

    use_color = sys.stdout.isatty() and not args.no_color
    for r in results:
        label = f"{COLORS[r.verdict]}{r.verdict}{RESET}" if use_color else r.verdict
        print(f"\n{r.url}\n  verdict: {label}   score: {r.score}/100")
        for reason in r.reasons:
            print(f"    {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
