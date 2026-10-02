"""Async, credential-free IPP sweep.

For each host: POST an anonymous Get-Printer-Attributes to the usual IPP
resource paths over ipp:// (631) and optionally ipps:// (631/443), and turn
the first successful answer into a PrinterRecord.
"""
from __future__ import annotations

import asyncio
import ipaddress
import itertools
import ssl
from dataclasses import asdict, dataclass, field
from typing import Iterable

from .ipp import (
    PRINTER_STATES,
    IppError,
    build_get_printer_attributes,
    parse_device_id,
    parse_response,
)

# Tried in order; first one that answers successful-ok wins.
DEFAULT_PATHS = ["/ipp/print", "/ipp", "/", "/ipp/printer", "/printer"]

# IPP status codes meaning "wrong resource path, try the next one".
_NOT_FOUND_STATUSES = {0x0400, 0x0406}  # bad-request, not-found


@dataclass
class PrinterRecord:
    ip: str
    port: int
    scheme: str  # ipp | ipps
    path: str
    ipp_version: str = ""
    make_model: str = ""
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    name: str = ""
    info: str = ""
    location: str = ""
    geo_location: str = ""
    organization: str = ""
    uuid: str = ""
    dns_sd_name: str = ""
    more_info: str = ""
    firmware: str = ""
    state: str = ""
    state_reasons: str = ""
    color: str = ""
    supplies: str = ""
    auth_supported: str = ""
    device_id: str = ""
    raw: dict = field(default_factory=dict, repr=False)

    def to_row(self) -> dict:
        row = asdict(self)
        row.pop("raw")
        return row


@dataclass
class ProbeResult:
    ip: str
    record: PrinterRecord | None = None
    open_ports: list[int] = field(default_factory=list)
    note: str = ""  # why no record: e.g. "auth required", "not IPP"


def _join(vals) -> str:
    return ", ".join(str(v) for v in vals if v not in ("", None))


def build_record(ip: str, port: int, scheme: str, path: str, resp) -> PrinterRecord:
    a = resp.attributes
    f = resp.first
    dev_id = f("printer-device-id", "")
    did = parse_device_id(dev_id)
    fw_names = a.get("printer-firmware-name", [])
    fw_vers = a.get("printer-firmware-string-version", [])
    firmware = _join(f"{n} {v}".strip() for n, v in itertools.zip_longest(fw_names, fw_vers, fillvalue=""))
    supplies = _join(
        f"{n}={lvl}%" if isinstance(lvl, int) and lvl >= 0 else f"{n}=?"
        for n, lvl in zip(a.get("marker-names", []), a.get("marker-levels", []))
    )
    state = f("printer-state")
    color = f("color-supported")
    return PrinterRecord(
        ip=ip,
        port=port,
        scheme=scheme,
        path=path,
        ipp_version=f"{resp.version[0]}.{resp.version[1]}",
        make_model=f("printer-make-and-model", ""),
        manufacturer=did.get("MFG") or did.get("MANUFACTURER", ""),
        model=did.get("MDL") or did.get("MODEL", ""),
        serial=did.get("SN") or did.get("SERN") or did.get("SERIALNUMBER", ""),
        name=f("printer-name", ""),
        info=f("printer-info", ""),
        location=f("printer-location", ""),
        geo_location=f("printer-geo-location", ""),
        organization=_join(a.get("printer-organization", []) + a.get("printer-organizational-unit", [])),
        uuid=f("printer-uuid", ""),
        dns_sd_name=f("printer-dns-sd-name", ""),
        more_info=f("printer-more-info", ""),
        firmware=firmware,
        state=PRINTER_STATES.get(state, str(state or "")),
        state_reasons=_join(a.get("printer-state-reasons", [])),
        color="" if color is None else ("yes" if color else "no"),
        supplies=supplies,
        auth_supported=_join(a.get("uri-authentication-supported", [])),
        device_id=dev_id,
        raw=a,
    )


class HttpError(Exception):
    def __init__(self, status: int, msg: str = ""):
        super().__init__(f"HTTP {status} {msg}".strip())
        self.status = status


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str], limit: int) -> bytes:
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = bytearray()
        while True:
            size_line = await reader.readline()
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            body += await reader.readexactly(size)
            await reader.readline()
            if len(body) > limit:
                raise IppError("response too large")
        return bytes(body)
    if "content-length" in headers:
        n = int(headers["content-length"])
        if n > limit:
            raise IppError("response too large")
        return await reader.readexactly(n)
    return await reader.read(limit)


async def ipp_post(
    host: str,
    port: int,
    path: str,
    payload: bytes,
    tls: bool,
    timeout: float,
    limit: int = 1 << 20,
) -> bytes:
    """Send one IPP request over HTTP/1.1 and return the IPP response body."""
    ctx = None
    if tls:
        # Printers almost always present self-signed certificates; we only
        # read public attributes, so certificate validation is not useful here.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    async def _do() -> bytes:
        reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
        try:
            hostport = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            head = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {hostport}\r\n"
                "Content-Type: application/ipp\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            writer.write(head + payload)
            await writer.drain()

            status_line = await reader.readline()
            parts = status_line.decode("latin-1").split(" ", 2)
            if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                raise IppError("not an HTTP response")
            status = int(parts[1])
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                k, _, v = line.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            # 100 Continue is not expected (we never send Expect), so anything
            # other than 200 is a failure for this path.
            if status != 200:
                raise HttpError(status, parts[2].strip() if len(parts) > 2 else "")
            return await _read_body(reader, headers, limit)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.wait_for(_do(), timeout)


async def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def probe_host(
    ip: str,
    *,
    use_tls: bool = False,
    connect_timeout: float = 1.5,
    timeout: float = 5.0,
    paths: list[str] = DEFAULT_PATHS,
    port: int = 631,
) -> ProbeResult:
    result = ProbeResult(ip)
    # (port, tls) combinations to try in order.
    attempts: list[tuple[int, bool]] = [(port, False)]
    if use_tls:
        attempts += [(port, True), (443, True)]

    checked: dict[int, bool] = {}
    notes: list[str] = []
    saw_ipp_not_found = False
    for p, tls in attempts:
        if p not in checked:
            checked[p] = await port_open(ip, p, connect_timeout)
            if checked[p]:
                result.open_ports.append(p)
        if not checked[p]:
            continue
        scheme = "ipps" if tls else "ipp"
        for path in paths:
            uri = f"{scheme}://{ip}:{p}{path}"
            try:
                body = await ipp_post(ip, p, path, build_get_printer_attributes(uri), tls, timeout)
                resp = parse_response(body)
            except HttpError as e:
                if e.status in (401, 403):
                    notes.append(f"{scheme}:{p} auth required")
                    break
                if e.status == 426:  # Upgrade Required -> TLS only
                    notes.append(f"{scheme}:{p} TLS required")
                    break
                continue  # 404/400 etc.: try next path
            except (IppError, OSError, asyncio.TimeoutError, ssl.SSLError, ValueError,
                    asyncio.IncompleteReadError):
                notes.append(f"{scheme}:{p} not IPP")
                break  # this port/scheme doesn't speak IPP; don't hammer it
            if resp.ok:
                result.record = build_record(ip, p, scheme, path, resp)
                return result
            if resp.status_code in _NOT_FOUND_STATUSES:
                saw_ipp_not_found = True
                continue
            notes.append(f"{scheme}:{p} IPP status 0x{resp.status_code:04x}")
            break
    if saw_ipp_not_found:
        # Speaks IPP but has no printer at the usual paths: typically a CUPS or
        # other print server whose queues live under /printers/<name>.
        notes.append("IPP server without printer at common paths (likely print server)")
    result.note = "; ".join(dict.fromkeys(notes)) or ("no IPP port open" if not result.open_ports else "no IPP path answered")
    return result


def expand_targets(specs: Iterable[str], max_hosts: int) -> list[str]:
    """Expand IPs / CIDRs into a de-duplicated host list."""
    seen: dict[str, None] = {}
    for spec in specs:
        spec = spec.split("#", 1)[0].strip()
        if not spec:
            continue
        net = ipaddress.ip_network(spec, strict=False)
        hosts = [net.network_address] if net.num_addresses == 1 else net.hosts()
        for h in hosts:
            seen[str(h)] = None
            if len(seen) > max_hosts:
                raise ValueError(f"more than {max_hosts} hosts; raise --max-hosts if intended")
    return list(seen)


async def scan(
    hosts: list[str],
    *,
    concurrency: int = 256,
    on_result=None,
    **probe_kwargs,
) -> list[ProbeResult]:
    sem = asyncio.Semaphore(concurrency)

    async def _one(ip: str) -> ProbeResult:
        async with sem:
            r = await probe_host(ip, **probe_kwargs)
        if on_result:
            on_result(r)
        return r

    return await asyncio.gather(*(_one(h) for h in hosts))
