"""CLI: python -m printer_discovery 10.10.0.0/24 -f subnets.txt --csv printers.csv"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys

from .scanner import DEFAULT_PATHS, PrinterRecord, ProbeResult, expand_targets, scan


def _args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="printer_discovery",
        description="Credential-free printer discovery via IPP Get-Printer-Attributes.",
    )
    p.add_argument("targets", nargs="*", help="IPs or CIDRs (e.g. 10.1.2.0/24)")
    p.add_argument("-f", "--file", action="append", default=[], help="file with one IP/CIDR per line")
    p.add_argument("--csv", help="write found printers to this CSV")
    p.add_argument("--json", help="write found printers (incl. all raw IPP attributes) to this JSON")
    p.add_argument("--tls", action="store_true", help="also try ipps:// on 631 and 443")
    p.add_argument("--port", type=int, default=631)
    p.add_argument("--path", action="append", default=[],
                   help="extra IPP resource path to try after the defaults (repeatable), e.g. /printers/Finance")
    p.add_argument("--concurrency", type=int, default=256)
    p.add_argument("--connect-timeout", type=float, default=1.5)
    p.add_argument("--timeout", type=float, default=5.0, help="per IPP request")
    p.add_argument("--max-hosts", type=int, default=65536)
    p.add_argument("--show-misses", action="store_true", help="log hosts with an open port but no IPP answer")
    return p.parse_args(argv)


def main(argv=None) -> int:
    a = _args(argv)
    specs = list(a.targets)
    for path in a.file:
        with open(path, encoding="utf-8") as fh:
            specs += fh.read().splitlines()
    if not specs:
        print("no targets given", file=sys.stderr)
        return 2
    try:
        hosts = expand_targets(specs, a.max_hosts)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"probing {len(hosts)} hosts ...", file=sys.stderr)

    def on_result(r: ProbeResult) -> None:
        if r.record:
            rec = r.record
            print(f"[+] {r.ip:<15} {rec.make_model or rec.model or '?'}  loc={rec.location!r}  sn={rec.serial or '-'}",
                  file=sys.stderr)
        elif a.show_misses and r.open_ports:
            print(f"[-] {r.ip:<15} ports={r.open_ports} {r.note}", file=sys.stderr)

    results = asyncio.run(
        scan(
            hosts,
            concurrency=a.concurrency,
            on_result=on_result,
            use_tls=a.tls,
            connect_timeout=a.connect_timeout,
            timeout=a.timeout,
            port=a.port,
            paths=DEFAULT_PATHS + a.path,
        )
    )
    printers = [r.record for r in results if r.record]
    print(f"done: {len(printers)} printers found out of {len(hosts)} hosts", file=sys.stderr)

    if a.csv:
        fields = list(PrinterRecord.__dataclass_fields__)
        fields.remove("raw")
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for rec in printers:
                w.writerow(rec.to_row())
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump([{**rec.to_row(), "raw": rec.raw} for rec in printers], fh, indent=2, default=str)
    if not a.csv and not a.json:
        json.dump([rec.to_row() for rec in printers], sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
