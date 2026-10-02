import asyncio
import struct
import unittest

from printer_discovery.ipp import (
    TAG_BEG_COLLECTION,
    TAG_END_COLLECTION,
    TAG_ENUM,
    TAG_INTEGER,
    TAG_KEYWORD,
    TAG_MEMBER_NAME,
    TAG_TEXT,
    TAG_TEXT_WITH_LANG,
    TAG_URI,
    _attr,
    build_get_printer_attributes,
    parse_device_id,
    parse_response,
)
from printer_discovery.scanner import expand_targets, probe_host


def fake_printer_response(request_id: int = 1) -> bytes:
    body = struct.pack(">BBHI", 2, 0, 0x0000, request_id)
    body += bytes([0x01])
    body += _attr(0x47, "attributes-charset", b"utf-8")
    body += _attr(0x48, "attributes-natural-language", b"en")
    body += bytes([0x04])  # printer-attributes group
    body += _attr(TAG_TEXT, "printer-make-and-model", b"HP LaserJet MFP M428fdw")
    body += _attr(TAG_TEXT, "printer-device-id", b"MFG:HP;MDL:LaserJet MFP M428fdw;SN:PHBXX12345;CMD:PJL,PCL;")
    tl = b"en" + struct.pack(">H", 14) + b"Floor 3 - Fin."
    body += _attr(TAG_TEXT_WITH_LANG, "printer-location", struct.pack(">H", 2) + tl)
    body += _attr(TAG_URI, "printer-uuid", b"urn:uuid:564e4333-4a31-3036-3838-a0b3cc010203")
    body += _attr(TAG_ENUM, "printer-state", struct.pack(">i", 3))
    body += _attr(TAG_KEYWORD, "printer-state-reasons", b"toner-low-warning")
    body += _attr(0x42, "marker-names", b"Black Cartridge")
    body += _attr(TAG_INTEGER, "marker-levels", struct.pack(">i", 12))
    # A collection whose members must not leak into the flat dict.
    body += _attr(TAG_BEG_COLLECTION, "media-col-default", b"")
    body += _attr(TAG_MEMBER_NAME, "", b"media-size")
    body += _attr(TAG_BEG_COLLECTION, "", b"")
    body += _attr(TAG_MEMBER_NAME, "", b"x-dimension")
    body += _attr(TAG_INTEGER, "", struct.pack(">i", 21000))
    body += _attr(TAG_END_COLLECTION, "", b"")
    body += _attr(TAG_END_COLLECTION, "", b"")
    body += _attr(0x22, "color-supported", b"\x00")
    body += bytes([0x03])
    return body


class ParseTests(unittest.TestCase):
    def test_request_roundtrips_through_parser(self):
        req = build_get_printer_attributes("ipp://1.2.3.4:631/ipp/print", request_id=7,
                                           attributes=["printer-name", "printer-location"])
        r = parse_response(req)  # same wire format, op-id sits where status would be
        self.assertEqual(r.request_id, 7)
        self.assertEqual(r.attributes["printer-uri"], ["ipp://1.2.3.4:631/ipp/print"])
        self.assertEqual(r.attributes["requested-attributes"], ["printer-name", "printer-location"])

    def test_parse_printer_response(self):
        r = parse_response(fake_printer_response())
        self.assertTrue(r.ok)
        self.assertEqual(r.first("printer-make-and-model"), "HP LaserJet MFP M428fdw")
        self.assertEqual(r.first("printer-location"), "Floor 3 - Fin.")
        self.assertEqual(r.first("printer-state"), 3)
        self.assertIs(r.first("color-supported"), False)
        # collections are skipped entirely, including their members
        self.assertNotIn("media-col-default", r.attributes)
        self.assertNotIn("x-dimension", r.attributes)

    def test_device_id(self):
        d = parse_device_id("MFG:HP;MDL:LaserJet;SN:ABC123;")
        self.assertEqual(d, {"MFG": "HP", "MDL": "LaserJet", "SN": "ABC123"})

    def test_expand_targets(self):
        self.assertEqual(expand_targets(["10.0.0.0/30", "10.0.0.1", "# c", "10.0.0.9"], 10),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.9"])
        with self.assertRaises(ValueError):
            expand_targets(["10.0.0.0/24"], 10)


class FakePrinter:
    """HTTP server that answers IPP only on /ipp (404 elsewhere), or 401 everywhere."""

    def __init__(self, mode: str = "ok"):
        self.mode = mode
        self.paths: list[str] = []

    async def handle(self, reader, writer):
        line = (await reader.readline()).decode()
        if not line:  # bare TCP port check
            writer.close()
            return
        path = line.split(" ")[1]
        self.paths.append(path)
        length = 0
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b""):
                break
            k, _, v = h.decode().partition(":")
            if k.lower() == "content-length":
                length = int(v)
        req = parse_response(await reader.readexactly(length))
        if self.mode == "auth":
            writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
        elif path != "/ipp":
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        else:
            body = fake_printer_response(req.request_id)
            # chunked, to exercise that code path
            mid = len(body) // 2
            chunks = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in (body[:mid], body[mid:]))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n" + chunks + b"0\r\n\r\n")
        await writer.drain()
        writer.close()


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, mode):
        fp = FakePrinter(mode)
        server = await asyncio.start_server(fp.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            res = await probe_host("127.0.0.1", port=port, timeout=2)
        return fp, res, port

    async def test_probe_finds_printer(self):
        fp, res, port = await self._run("ok")
        rec = res.record
        self.assertIsNotNone(rec, res.note)
        self.assertEqual(fp.paths, ["/ipp/print", "/ipp"])
        self.assertEqual((rec.port, rec.scheme, rec.path), (port, "ipp", "/ipp"))
        self.assertEqual(rec.manufacturer, "HP")
        self.assertEqual(rec.serial, "PHBXX12345")
        self.assertEqual(rec.location, "Floor 3 - Fin.")
        self.assertEqual(rec.state, "idle")
        self.assertEqual(rec.supplies, "Black Cartridge=12%")
        self.assertEqual(rec.color, "no")

    async def test_probe_auth_required(self):
        fp, res, _ = await self._run("auth")
        self.assertIsNone(res.record)
        self.assertIn("auth required", res.note)
        self.assertEqual(len(fp.paths), 1)  # stops after first 401

    async def test_closed_port(self):
        res = await probe_host("127.0.0.1", port=1, connect_timeout=0.5)
        self.assertIsNone(res.record)
        self.assertEqual(res.note, "no IPP port open")


if __name__ == "__main__":
    unittest.main()
