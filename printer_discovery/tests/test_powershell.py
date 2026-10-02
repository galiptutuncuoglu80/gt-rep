"""Parity test: the PowerShell port must produce the same CSV as the Python scanner.

Skipped when no PowerShell (pwsh) is on PATH.
"""
import asyncio
import csv
import os
import shutil
import tempfile
import unittest

from printer_discovery.scanner import PrinterRecord, scan
from printer_discovery.tests.test_ipp import FakePrinter

PWSH = shutil.which("pwsh")
SCRIPT = os.path.join(os.path.dirname(__file__), "..", "powershell", "Invoke-PrinterDiscovery.ps1")


@unittest.skipUnless(PWSH, "pwsh not installed")
class PowerShellParityTests(unittest.IsolatedAsyncioTestCase):
    async def _pwsh(self, port, *extra):
        proc = await asyncio.create_subprocess_exec(
            PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", SCRIPT,
            "-Target", "127.0.0.1", "-Port", str(port), "-TimeoutMs", "3000", *extra,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), 120)
        self.assertEqual(proc.returncode, 0, err.decode())
        return out.decode()

    async def test_same_csv_as_python(self):
        fp = FakePrinter("ok")
        server = await asyncio.start_server(fp.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        with tempfile.TemporaryDirectory() as d:
            ps_csv = os.path.join(d, "ps.csv")
            async with server:
                await self._pwsh(port, "-CsvPath", ps_csv)
                py = await scan(["127.0.0.1"], port=port, timeout=3)

            with open(ps_csv, encoding="utf-8") as fh:
                raw = fh.read()
            self.assertFalse(raw.startswith("﻿"), "CSV must not have a BOM")
            rows = list(csv.DictReader(raw.splitlines()))

        expected = py[0].record.to_row()
        self.assertEqual(len(rows), 1)
        self.assertEqual(list(rows[0]), [f for f in PrinterRecord.__dataclass_fields__ if f != "raw"])
        self.assertEqual(rows[0], {k: str(v) for k, v in expected.items()})
        self.assertEqual(rows[0]["serial"], "PHBXX12345")
        self.assertEqual(rows[0]["supplies"], "Black Cartridge=12%")

    async def test_auth_required_is_reported(self):
        fp = FakePrinter("auth")
        server = await asyncio.start_server(fp.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            out = await self._pwsh(port, "-ShowMisses")
        self.assertIn("auth required", out)
        self.assertIn("done: 0 printers found", out)
        self.assertEqual(fp.paths, ["/ipp/print"])  # stops after first 401
