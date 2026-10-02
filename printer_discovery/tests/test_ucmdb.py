"""Tests for the UCMDB Jython adapter (printer_discovery/ucmdb/printer_by_ipp.py).

- CPython: probe logic parity with the Python scanner (socket transport).
- DiscoveryMain / OSH building with stand-in UCMDB modules.
- Jython: the real Java transport, when JYTHON_JAR points at a
  jython-standalone 2.7 jar and java is on PATH (skipped otherwise).
"""
import asyncio
import json
import os
import shutil
import socket
import sys
import types
import unittest

from printer_discovery.scanner import scan
from printer_discovery.tests.test_ipp import FakePrinter

UCMDB_DIR = os.path.join(os.path.dirname(__file__), "..", "ucmdb")
sys.path.insert(0, UCMDB_DIR)
import printer_by_ipp  # noqa: E402

JYTHON_JAR = os.environ.get("JYTHON_JAR")
JAVA = shutil.which("java")


class SocketTransport:
    def port_open(self, ip, port):
        try:
            socket.create_connection((ip, port), 1).close()
            return True
        except OSError:
            return False

    def exchange(self, ip, port, tls, request):
        assert not tls
        s = socket.create_connection((ip, port), 2)
        s.settimeout(3)
        try:
            s.sendall(request)
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                if printer_by_ipp.http_response_complete(data):
                    break
            return data
        finally:
            s.close()


async def _start(mode):
    fp = FakePrinter(mode)
    server = await asyncio.start_server(fp.handle, "127.0.0.1", 0)
    return fp, server, server.sockets[0].getsockname()[1]


class AdapterProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_record_as_python_scanner(self):
        fp, server, port = await _start("ok")
        async with server:
            rec, attrs, open_ports, note = await asyncio.to_thread(
                printer_by_ipp.probe_host, "127.0.0.1", SocketTransport(), port)
            py = await scan(["127.0.0.1"], port=port, timeout=3)
        self.assertEqual(note, "")
        self.assertEqual(rec, py[0].record.to_row())
        self.assertEqual(rec["serial"], "PHBXX12345")
        self.assertEqual(fp.paths[-2:], ["/ipp/print", "/ipp"])

    async def test_auth_required(self):
        fp, server, port = await _start("auth")
        async with server:
            rec, _, open_ports, note = await asyncio.to_thread(
                printer_by_ipp.probe_host, "127.0.0.1", SocketTransport(), port)
        self.assertIsNone(rec)
        self.assertEqual(open_ports, [port])
        self.assertIn("auth required", note)


class FakeOSH:
    def __init__(self, ci_type, **attrs):
        self.ci_type = ci_type
        self.attrs = dict(attrs)

    def setStringAttribute(self, k, v):
        self.attrs[k] = v

    def setListAttribute(self, k, v):
        self.attrs[k] = list(v)


class FakeVector(list):
    def add(self, osh):
        self.append(osh)


def _install_fake_ucmdb_modules():
    vectors = types.ModuleType("appilog.common.system.types.vectors")
    vectors.ObjectStateHolderVector = FakeVector
    modeling = types.ModuleType("modeling")
    modeling.SERVICEADDRESS_TYPE_TCP = 1
    modeling.createHostOSH = lambda ip, cls: FakeOSH(cls, ip=ip)
    modeling.createIpOSH = lambda ip: FakeOSH("ip_address", name=ip)
    modeling.createLinkOSH = lambda cls, a, b: FakeOSH(cls, end1=a, end2=b)
    modeling.createServiceAddressOsh = lambda h, ip, port, t, name: FakeOSH(
        "ip_service_endpoint", host=h, ip=ip, port=port, name=name)
    logger = types.ModuleType("logger")
    logger.messages = []
    for lvl in ("debug", "info", "warn", "error", "debugException"):
        setattr(logger, lvl, lambda msg, *a, _l=lvl: logger.messages.append((_l, msg)))
    mods = {"appilog": types.ModuleType("appilog"),
            "appilog.common": types.ModuleType("appilog.common"),
            "appilog.common.system": types.ModuleType("appilog.common.system"),
            "appilog.common.system.types": types.ModuleType("appilog.common.system.types"),
            "appilog.common.system.types.vectors": vectors,
            "modeling": modeling, "logger": logger}
    saved = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)
    return saved


class FakeFramework:
    def __init__(self, ip, params):
        self.ip = ip
        self.params = params
        self.warnings = []

    def getDestinationAttribute(self, name):
        assert name == "ip_address"
        return self.ip

    def getParameter(self, name):
        return self.params.get(name)

    def reportWarning(self, msg):
        self.warnings.append(msg)


class DiscoveryMainTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved = _install_fake_ucmdb_modules()
        # DiscoveryMain builds a JavaTransport; swap in the socket one.
        self._orig = printer_by_ipp.JavaTransport
        printer_by_ipp.JavaTransport = lambda *a: SocketTransport()

    def tearDown(self):
        printer_by_ipp.JavaTransport = self._orig
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    async def test_reports_printer_ip_and_endpoint(self):
        _, server, port = await _start("ok")
        fw = FakeFramework("127.0.0.1", {"ippPort": str(port), "printerCiType": "netprinter"})
        async with server:
            oshv = await asyncio.to_thread(printer_by_ipp.DiscoveryMain, fw)
        types_ = [o.ci_type for o in oshv]
        self.assertEqual(types_, ["netprinter", "ip_address", "containment", "ip_service_endpoint"])
        host = oshv[0]
        self.assertEqual(host.attrs["discovered_vendor"], "HP")
        self.assertEqual(host.attrs["discovered_model"], "LaserJet MFP M428fdw")
        self.assertEqual(host.attrs["serial_number"], "PHBXX12345")
        self.assertEqual(host.attrs["node_role"], ["printer"])
        self.assertIn("Location: Floor 3 - Fin.", host.attrs["description"])
        self.assertEqual(oshv[3].attrs["port"], port)
        self.assertEqual(fw.warnings, [])

    async def test_auth_required_warns_and_reports_nothing(self):
        _, server, port = await _start("auth")
        fw = FakeFramework("127.0.0.1", {"ippPort": str(port)})
        async with server:
            oshv = await asyncio.to_thread(printer_by_ipp.DiscoveryMain, fw)
        self.assertEqual(list(oshv), [])
        self.assertEqual(len(fw.warnings), 1)
        self.assertIn("auth required", fw.warnings[0])

    def test_closed_port_is_silent(self):
        fw = FakeFramework("127.0.0.1", {"ippPort": "1"})
        oshv = printer_by_ipp.DiscoveryMain(fw)
        self.assertEqual(list(oshv), [])
        self.assertEqual(fw.warnings, [])


@unittest.skipUnless(JYTHON_JAR and JAVA, "set JYTHON_JAR to a jython-standalone 2.7 jar")
class JythonTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_java_transport_matches_python_scanner(self):
        fp, server, port = await _start("ok")
        async with server:
            proc = await asyncio.create_subprocess_exec(
                JAVA, "-jar", JYTHON_JAR, os.path.join(UCMDB_DIR, "jython_probe.py"), "127.0.0.1", str(port),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), 180)
            py = await scan(["127.0.0.1"], port=port, timeout=3)
        self.assertEqual(proc.returncode, 0, err.decode())
        got = json.loads(out.decode().strip().splitlines()[-1])
        self.assertEqual(got["record"], py[0].record.to_row())


class RecordTests(unittest.TestCase):
    def test_missing_color_is_blank_not_no(self):
        # Regression: an `x and a or b` idiom turned a missing value into "no".
        rec = printer_by_ipp.build_record("1.2.3.4", 631, "ipp", "/ipp", "2.0", {})
        self.assertEqual(rec["color"], "")
        self.assertEqual(rec["state"], "")

    def test_request_with_zero_bytes_roundtrips(self):
        # Regression: zero bytes were mangled when converted for Java.
        req = printer_by_ipp.build_get_printer_attributes("ipp://1.2.3.4:631/ipp", request_id=1)
        self.assertIn(b"\x00", req)
        _, _, attrs = printer_by_ipp.parse_response(req)
        self.assertEqual(attrs["printer-uri"], ["ipp://1.2.3.4:631/ipp"])
