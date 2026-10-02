"""Minimal IPP (RFC 8010/8011) encoder/decoder for Get-Printer-Attributes.

Only what discovery needs: build one anonymous request, parse the response
into a flat ``{name: [values]}`` dict. Collection values are skipped.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

OP_GET_PRINTER_ATTRIBUTES = 0x000B

# Delimiter tags
TAG_OPERATION = 0x01
TAG_END = 0x03

# Value tags
TAG_INTEGER = 0x21
TAG_BOOLEAN = 0x22
TAG_ENUM = 0x23
TAG_OCTET_STRING = 0x30
TAG_DATETIME = 0x31
TAG_RESOLUTION = 0x32
TAG_RANGE = 0x33
TAG_BEG_COLLECTION = 0x34
TAG_TEXT_WITH_LANG = 0x35
TAG_NAME_WITH_LANG = 0x36
TAG_END_COLLECTION = 0x37
TAG_TEXT = 0x41
TAG_NAME = 0x42
TAG_KEYWORD = 0x44
TAG_URI = 0x45
TAG_CHARSET = 0x47
TAG_LANGUAGE = 0x48
TAG_MIME = 0x49
TAG_MEMBER_NAME = 0x4A

_STRING_TAGS = {0x41, 0x42, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49}

# Attributes useful for inventory. Printers silently ignore ones they lack.
DEFAULT_ATTRIBUTES = [
    "printer-make-and-model",
    "printer-device-id",
    "printer-name",
    "printer-info",
    "printer-location",
    "printer-geo-location",
    "printer-organization",
    "printer-organizational-unit",
    "printer-uuid",
    "printer-dns-sd-name",
    "printer-more-info",
    "printer-uri-supported",
    "printer-firmware-name",
    "printer-firmware-string-version",
    "printer-state",
    "printer-state-reasons",
    "printer-is-accepting-jobs",
    "printer-up-time",
    "color-supported",
    "marker-names",
    "marker-levels",
    "marker-colors",
    "marker-types",
    "ipp-versions-supported",
    "uri-security-supported",
    "uri-authentication-supported",
]

PRINTER_STATES = {3: "idle", 4: "processing", 5: "stopped"}


class IppError(Exception):
    pass


def _attr(tag: int, name: str, value: bytes) -> bytes:
    n = name.encode()
    return struct.pack(">BH", tag, len(n)) + n + struct.pack(">H", len(value)) + value


def build_get_printer_attributes(
    printer_uri: str,
    request_id: int = 1,
    attributes: list[str] | None = None,
    version: tuple[int, int] = (2, 0),
) -> bytes:
    attributes = attributes or DEFAULT_ATTRIBUTES
    body = struct.pack(">BBHI", version[0], version[1], OP_GET_PRINTER_ATTRIBUTES, request_id)
    body += bytes([TAG_OPERATION])
    body += _attr(TAG_CHARSET, "attributes-charset", b"utf-8")
    body += _attr(TAG_LANGUAGE, "attributes-natural-language", b"en")
    body += _attr(TAG_URI, "printer-uri", printer_uri.encode())
    body += _attr(TAG_NAME, "requesting-user-name", b"discovery")
    for i, a in enumerate(attributes):
        # Additional values of a 1setOf carry an empty name.
        body += _attr(TAG_KEYWORD, "requested-attributes" if i == 0 else "", a.encode())
    body += bytes([TAG_END])
    return body


@dataclass
class IppResponse:
    version: tuple[int, int]
    status_code: int
    request_id: int
    attributes: dict[str, list] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        # 0x0000-0x00FF are successful-ok* codes.
        return self.status_code < 0x0100

    def first(self, name: str, default=None):
        vals = self.attributes.get(name)
        return vals[0] if vals else default


def _decode_value(tag: int, raw: bytes):
    if tag in (TAG_INTEGER, TAG_ENUM) and len(raw) == 4:
        return struct.unpack(">i", raw)[0]
    if tag == TAG_BOOLEAN and len(raw) == 1:
        return bool(raw[0])
    if tag in _STRING_TAGS:
        return raw.decode("utf-8", "replace")
    if tag in (TAG_TEXT_WITH_LANG, TAG_NAME_WITH_LANG) and len(raw) >= 4:
        llen = struct.unpack(">H", raw[:2])[0]
        tlen = struct.unpack(">H", raw[2 + llen : 4 + llen])[0]
        return raw[4 + llen : 4 + llen + tlen].decode("utf-8", "replace")
    if tag == TAG_RESOLUTION and len(raw) == 9:
        x, y, unit = struct.unpack(">iiB", raw)
        return f"{x}x{y}{'dpi' if unit == 3 else 'dpcm'}"
    if tag == TAG_RANGE and len(raw) == 8:
        return struct.unpack(">ii", raw)
    if tag == TAG_OCTET_STRING:
        return raw.decode("utf-8", "replace")
    return raw.hex()


def parse_response(data: bytes) -> IppResponse:
    if len(data) < 8:
        raise IppError(f"IPP response too short ({len(data)} bytes)")
    major, minor, status, req_id = struct.unpack(">BBHI", data[:8])
    resp = IppResponse((major, minor), status, req_id)
    pos = 8
    current: str | None = None
    depth = 0  # >0 while inside a collection, whose members we skip
    try:
        while pos < len(data):
            tag = data[pos]
            pos += 1
            if tag == TAG_END:
                break
            if tag < 0x10:  # group delimiter
                current = None
                continue
            nlen = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            name = data[pos : pos + nlen].decode("utf-8", "replace")
            pos += nlen
            vlen = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            raw = data[pos : pos + vlen]
            pos += vlen
            if len(raw) != vlen:
                raise IppError("truncated attribute value")

            if tag == TAG_BEG_COLLECTION:
                depth += 1
                if depth == 1 and name:
                    current = name
                continue
            if tag == TAG_END_COLLECTION:
                depth = max(0, depth - 1)
                continue
            if depth:
                continue
            if name:
                current = name
            if current is None:
                continue
            resp.attributes.setdefault(current, []).append(_decode_value(tag, raw))
    except struct.error as e:
        raise IppError(f"malformed IPP response: {e}") from e
    return resp


def parse_device_id(device_id: str) -> dict[str, str]:
    """Parse an IEEE 1284 device ID ("MFG:HP;MDL:LaserJet;SN:ABC;") into a dict."""
    out: dict[str, str] = {}
    for part in device_id.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().upper()] = v.strip()
    return out
