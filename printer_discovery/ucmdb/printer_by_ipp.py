# coding=utf-8
"""
UCMDB discovery adapter script: credential-free printer discovery via IPP.

Runs on the Data Flow Probe (Jython 2.7). Triggered per IP address. Sends an
anonymous IPP Get-Printer-Attributes request to tcp/631 (optionally ipps on
631/443) and reports a printer Node with vendor, model, serial number,
location, the IP address and the IPP service endpoint.

Read-only: nothing is printed or changed on the device and no credentials
are used.

Same probe logic as the Python (printer_discovery/scanner.py) and PowerShell
(printer_discovery/powershell/) versions. The IPP code below is plain
Python 2/3 so it can be unit-tested outside UCMDB; only the transport
(Java sockets) and DiscoveryMain depend on the probe runtime.

Adapter parameters (all optional):
  ippPort            default 631
  useTls             'true' to also try ipps:// on ippPort and 443 (default false)
  extraPaths         comma-separated extra IPP paths, e.g. /printers/Finance
  connectTimeoutMs   default 1500
  timeoutMs          default 5000
  printerCiType      CI type for the printer node (default netprinter)
  reportServiceEndpoint  'false' to skip the tcp/631 service endpoint CI
"""
import struct

DEFAULT_PATHS = ['/ipp/print', '/ipp', '/', '/ipp/printer', '/printer']

# Attributes useful for inventory. Printers silently ignore ones they lack.
DEFAULT_ATTRIBUTES = [
    'printer-make-and-model', 'printer-device-id', 'printer-name', 'printer-info',
    'printer-location', 'printer-geo-location', 'printer-organization',
    'printer-organizational-unit', 'printer-uuid', 'printer-dns-sd-name', 'printer-more-info',
    'printer-uri-supported', 'printer-firmware-name', 'printer-firmware-string-version',
    'printer-state', 'printer-state-reasons', 'printer-is-accepting-jobs', 'printer-up-time',
    'color-supported', 'marker-names', 'marker-levels', 'marker-colors', 'marker-types',
    'ipp-versions-supported', 'uri-security-supported', 'uri-authentication-supported',
]

PRINTER_STATES = {3: 'idle', 4: 'processing', 5: 'stopped'}

_STRING_TAGS = (0x41, 0x42, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49)
_NOT_FOUND_STATUSES = (0x0400, 0x0406)  # bad-request, not-found
_MAX_RESPONSE = 1024 * 1024


class IppError(Exception):
    pass


class HttpStatusError(Exception):
    def __init__(self, status):
        Exception.__init__(self, 'HTTP %d' % status)
        self.status = status


# ---------------------------------------------------------------------------
# IPP encoding / decoding (pure Python 2/3)
# ---------------------------------------------------------------------------

def _to_bytes(s):
    if isinstance(s, bytes):
        return s
    return s.encode('utf-8')


def _attr(tag, name, value):
    n = _to_bytes(name)
    v = _to_bytes(value)
    return struct.pack('>BH', tag, len(n)) + n + struct.pack('>H', len(v)) + v


def build_get_printer_attributes(printer_uri, request_id=1, attributes=None):
    attributes = attributes or DEFAULT_ATTRIBUTES
    out = bytearray(struct.pack('>BBHI', 2, 0, 0x000B, request_id))
    out.extend(b'\x01')
    out.extend(_attr(0x47, 'attributes-charset', 'utf-8'))
    out.extend(_attr(0x48, 'attributes-natural-language', 'en'))
    out.extend(_attr(0x45, 'printer-uri', printer_uri))
    out.extend(_attr(0x42, 'requesting-user-name', 'discovery'))
    for i, a in enumerate(attributes):
        # Additional values of a 1setOf carry an empty name.
        if i == 0:
            out.extend(_attr(0x44, 'requested-attributes', a))
        else:
            out.extend(_attr(0x44, '', a))
    out.extend(b'\x03')
    return bytes(out)


def _u16(data, pos):
    if pos + 2 > len(data):
        raise IppError('malformed IPP response: truncated')
    return struct.unpack('>H', bytes(data[pos:pos + 2]))[0]


def _i32(data, pos):
    if pos + 4 > len(data):
        raise IppError('malformed IPP response: truncated')
    return struct.unpack('>i', bytes(data[pos:pos + 4]))[0]


def _decode_value(tag, raw):
    if tag in (0x21, 0x23) and len(raw) == 4:
        return _i32(raw, 0)
    if tag == 0x22 and len(raw) == 1:
        return raw[0] != 0
    if tag in _STRING_TAGS or tag == 0x30:
        return bytes(raw).decode('utf-8', 'replace')
    if tag in (0x35, 0x36) and len(raw) >= 4:
        llen = _u16(raw, 0)
        tlen = _u16(raw, 2 + llen)
        return bytes(raw[4 + llen:4 + llen + tlen]).decode('utf-8', 'replace')
    if tag == 0x32 and len(raw) == 9:
        unit = 'dpi' if raw[8] == 3 else 'dpcm'
        return '%dx%d%s' % (_i32(raw, 0), _i32(raw, 4), unit)
    if tag == 0x33 and len(raw) == 8:
        return '%d-%d' % (_i32(raw, 0), _i32(raw, 4))
    return ''.join('%02x' % b for b in raw)


def parse_response(data):
    """Returns (version, status_code, {name: [values]}). Collections are skipped."""
    data = bytearray(data)
    if len(data) < 8:
        raise IppError('IPP response too short (%d bytes)' % len(data))
    version = '%d.%d' % (data[0], data[1])
    status = _u16(data, 2)
    attrs = {}
    pos = 8
    current = None
    depth = 0  # >0 while inside a collection, whose members we skip
    while pos < len(data):
        tag = data[pos]
        pos += 1
        if tag == 0x03:
            break
        if tag < 0x10:  # group delimiter
            current = None
            continue
        nlen = _u16(data, pos)
        pos += 2
        if pos + nlen > len(data):
            raise IppError('malformed IPP response: truncated name')
        name = bytes(data[pos:pos + nlen]).decode('utf-8', 'replace')
        pos += nlen
        vlen = _u16(data, pos)
        pos += 2
        if pos + vlen > len(data):
            raise IppError('malformed IPP response: truncated value')
        raw = data[pos:pos + vlen]
        pos += vlen
        if tag == 0x34:
            depth += 1
            if depth == 1 and name:
                current = name
            continue
        if tag == 0x37:
            depth = max(0, depth - 1)
            continue
        if depth:
            continue
        if name:
            current = name
        if current is None:
            continue
        attrs.setdefault(current, []).append(_decode_value(tag, raw))
    return version, status, attrs


def parse_device_id(device_id):
    """IEEE 1284 device ID ("MFG:HP;MDL:LaserJet;SN:ABC;") -> dict."""
    out = {}
    for part in (device_id or '').split(';'):
        if ':' in part:
            k, v = part.split(':', 1)
            out[k.strip().upper()] = v.strip()
    return out


def _join(vals):
    return ', '.join(['%s' % v for v in vals if v not in ('', None)])


def build_record(ip, port, scheme, path, version, attrs):
    """Same fields and values as the Python/PowerShell CSV output."""
    def first(n, default=''):
        vals = attrs.get(n)
        if vals:
            return vals[0]
        return default

    dev_id = first('printer-device-id')
    did = parse_device_id(dev_id)

    def pick(*keys):
        for k in keys:
            if did.get(k):
                return did[k]
        return ''

    fw_names = attrs.get('printer-firmware-name', [])
    fw_vers = attrs.get('printer-firmware-string-version', [])
    fw = []
    for i in range(max(len(fw_names), len(fw_vers))):
        n = '%s' % fw_names[i] if i < len(fw_names) else ''
        v = '%s' % fw_vers[i] if i < len(fw_vers) else ''
        fw.append(('%s %s' % (n, v)).strip())

    supplies = []
    for n, lvl in zip(attrs.get('marker-names', []), attrs.get('marker-levels', [])):
        if isinstance(lvl, int) and not isinstance(lvl, bool) and lvl >= 0:
            supplies.append('%s=%d%%' % (n, lvl))
        else:
            supplies.append('%s=?' % n)

    state = first('printer-state', None)
    color = first('color-supported', None)
    return {
        'ip': ip,
        'port': port,
        'scheme': scheme,
        'path': path,
        'ipp_version': version,
        'make_model': first('printer-make-and-model'),
        'manufacturer': pick('MFG', 'MANUFACTURER'),
        'model': pick('MDL', 'MODEL'),
        'serial': pick('SN', 'SERN', 'SERIALNUMBER'),
        'name': first('printer-name'),
        'info': first('printer-info'),
        'location': first('printer-location'),
        'geo_location': first('printer-geo-location'),
        'organization': _join(attrs.get('printer-organization', []) + attrs.get('printer-organizational-unit', [])),
        'uuid': first('printer-uuid'),
        'dns_sd_name': first('printer-dns-sd-name'),
        'more_info': first('printer-more-info'),
        'firmware': _join(fw),
        'state': PRINTER_STATES.get(state, '' if state is None else '%s' % state),
        'state_reasons': _join(attrs.get('printer-state-reasons', [])),
        'color': '' if color is None else ('yes' if color else 'no'),
        'supplies': _join(supplies),
        'auth_supported': _join(attrs.get('uri-authentication-supported', [])),
        'device_id': dev_id,
    }


# ---------------------------------------------------------------------------
# HTTP framing (pure Python 2/3)
# ---------------------------------------------------------------------------

def build_http_request(ip, port, path, payload):
    head = ('POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/ipp\r\n'
            'Content-Length: %d\r\nConnection: close\r\n\r\n') % (path, ip, port, len(payload))
    return head.encode('ascii') + payload


def _split_head(data):
    i = data.find(b'\r\n\r\n')
    if i < 0:
        return None, None
    head = bytes(data[:i]).decode('latin-1')
    headers = {}
    for line in head.split('\r\n')[1:]:
        k, _, v = line.partition(':')
        headers[k.strip().lower()] = v.strip()
    return head, (i + 4, headers)


def http_response_complete(data):
    """True once a full response is buffered (for servers ignoring Connection: close)."""
    head, rest = _split_head(data)
    if head is None:
        return False
    start, headers = rest
    if 'content-length' in headers:
        return len(data) - start >= int(headers['content-length'])
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        return data.endswith(b'0\r\n\r\n')
    return False


def parse_http_response(data):
    """Returns the body of a 200 response; raises HttpStatusError / IppError otherwise."""
    data = bytes(data)
    head, rest = _split_head(data)
    if head is None or not head.startswith('HTTP/'):
        raise IppError('not an HTTP response')
    parts = head.split('\r\n', 1)[0].split(' ', 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        raise IppError('not an HTTP response')
    if status != 200:
        raise HttpStatusError(status)
    start, headers = rest
    body = data[start:]
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        out = bytearray()
        pos = 0
        while pos < len(body):
            eol = body.find(b'\r\n', pos)
            if eol < 0:
                break
            size_text = bytes(body[pos:eol]).decode('latin-1').split(';')[0].strip()
            size = int(size_text, 16) if size_text else 0
            if size == 0:
                break
            pos = eol + 2
            if pos + size > len(body):
                raise IppError('truncated HTTP chunk')
            out.extend(body[pos:pos + size])
            pos += size + 2
        return bytes(out)
    if 'content-length' in headers:
        body = body[:int(headers['content-length'])]
    return body


# ---------------------------------------------------------------------------
# Probe logic (transport injected so it can be tested outside UCMDB)
# ---------------------------------------------------------------------------

def probe_host(ip, transport, port=631, use_tls=False, paths=None):
    """
    transport must provide port_open(ip, port) -> bool and
    exchange(ip, port, tls, request_bytes) -> raw HTTP response bytes.

    Returns (record_or_None, raw_attrs_or_None, open_ports, note).
    """
    paths = paths or DEFAULT_PATHS
    attempts = [(port, False)]
    if use_tls:
        attempts += [(port, True), (443, True)]
    checked = {}
    open_ports = []
    notes = []
    saw_ipp_not_found = False
    for p, tls in attempts:
        if p not in checked:
            checked[p] = transport.port_open(ip, p)
            if checked[p]:
                open_ports.append(p)
        if not checked[p]:
            continue
        scheme = 'ipps' if tls else 'ipp'
        for path in paths:
            uri = '%s://%s:%d%s' % (scheme, ip, p, path)
            req = build_http_request(ip, p, path, build_get_printer_attributes(uri))
            try:
                body = parse_http_response(transport.exchange(ip, p, tls, req))
                version, status, attrs = parse_response(body)
            except HttpStatusError as e:
                if e.status in (401, 403):
                    notes.append('%s:%d auth required' % (scheme, p))
                    break
                if e.status == 426:
                    notes.append('%s:%d TLS required' % (scheme, p))
                    break
                continue  # 404/400 etc.: try next path
            except Exception:
                notes.append('%s:%d not IPP' % (scheme, p))
                break  # this port/scheme doesn't speak IPP; don't hammer it
            if status < 0x0100:
                return build_record(ip, p, scheme, path, version, attrs), attrs, open_ports, ''
            if status in _NOT_FOUND_STATUSES:
                saw_ipp_not_found = True
                continue
            notes.append('%s:%d IPP status 0x%04x' % (scheme, p, status))
            break
    if saw_ipp_not_found:
        notes.append('IPP server without printer at common paths (likely print server)')
    uniq = []
    for n in notes:
        if n not in uniq:
            uniq.append(n)
    note = '; '.join(uniq)
    if not note:
        note = 'no IPP path answered' if open_ports else 'no IPP port open'
    return None, None, open_ports, note


class JavaTransport:
    """Java socket transport used on the probe (Jython)."""

    def __init__(self, connect_timeout_ms=1500, timeout_ms=5000):
        self.connect_timeout_ms = connect_timeout_ms
        self.timeout_ms = timeout_ms

    def _connect(self, ip, port):
        from java.net import Socket, InetSocketAddress
        s = Socket()
        s.connect(InetSocketAddress(ip, port), self.connect_timeout_ms)
        s.setSoTimeout(self.timeout_ms)
        return s

    def port_open(self, ip, port):
        try:
            s = self._connect(ip, port)
        except Exception:
            return False
        try:
            s.close()
        except Exception:
            pass
        return True

    def exchange(self, ip, port, tls, request):
        import jarray
        from java.io import ByteArrayOutputStream
        from java.lang import System
        sock = self._connect(ip, port)
        try:
            if tls:
                sock = _trust_all_socket_factory().createSocket(sock, ip, port, True)
                sock.setSoTimeout(self.timeout_ms)
                sock.startHandshake()
            out = sock.getOutputStream()
            out.write(jarray.array([b if b < 128 else b - 256 for b in bytearray(request)], 'b'))
            out.flush()
            inp = sock.getInputStream()
            buf = jarray.zeros(65536, 'b')
            bos = ByteArrayOutputStream()
            deadline = System.currentTimeMillis() + self.timeout_ms
            data = bytearray()
            while True:
                n = inp.read(buf)
                if n < 0:
                    break
                bos.write(buf, 0, n)
                if bos.size() > _MAX_RESPONSE:
                    raise IppError('response too large')
                data = bytearray([b & 0xff for b in bos.toByteArray()])
                if http_response_complete(bytes(data)):
                    break
                if System.currentTimeMillis() > deadline:
                    raise IppError('timeout')
            return bytes(data)
        finally:
            try:
                sock.close()
            except Exception:
                pass


_SSL_FACTORY = []


def _trust_all_socket_factory():
    # Printers almost always present self-signed certificates and we only read
    # public attributes, so certificate validation is skipped for ipps://.
    if not _SSL_FACTORY:
        from javax.net.ssl import SSLContext, X509TrustManager

        class TrustAll(X509TrustManager):
            def checkClientTrusted(self, chain, auth_type):
                pass

            def checkServerTrusted(self, chain, auth_type):
                pass

            def getAcceptedIssuers(self):
                return None

        ctx = SSLContext.getInstance('TLS')
        ctx.init(None, [TrustAll()], None)
        _SSL_FACTORY.append(ctx.getSocketFactory())
    return _SSL_FACTORY[0]


# ---------------------------------------------------------------------------
# UCMDB entry point
# ---------------------------------------------------------------------------

def _param(Framework, name, default):
    try:
        v = Framework.getParameter(name)
    except Exception:
        v = None
    if v is None or ('%s' % v).strip() == '':
        return default
    return ('%s' % v).strip()


def build_oshv(record, ci_type, report_endpoint):
    from appilog.common.system.types.vectors import ObjectStateHolderVector
    import modeling

    oshv = ObjectStateHolderVector()
    ip = record['ip']
    host = modeling.createHostOSH(ip, ci_type)
    vendor = record['manufacturer']
    model = record['model'] or record['make_model']
    if vendor:
        host.setStringAttribute('discovered_vendor', vendor)
    if model:
        host.setStringAttribute('discovered_model', model)
    if record['serial']:
        host.setStringAttribute('serial_number', record['serial'])
    if record['firmware']:
        host.setStringAttribute('discovered_os_version', record['firmware'])
    desc = []
    if record['make_model']:
        desc.append(record['make_model'])
    if record['name']:
        desc.append('IPP name: %s' % record['name'])
    if record['location']:
        desc.append('Location: %s' % record['location'])
    if record['uuid']:
        desc.append(record['uuid'])
    if desc:
        host.setStringAttribute('description', ' | '.join(desc))
    try:
        host.setListAttribute('node_role', ['printer'])
    except Exception:
        pass
    oshv.add(host)

    ip_osh = modeling.createIpOSH(ip)
    oshv.add(ip_osh)
    oshv.add(modeling.createLinkOSH('containment', host, ip_osh))
    if report_endpoint:
        oshv.add(modeling.createServiceAddressOsh(host, ip, record['port'],
                                                  modeling.SERVICEADDRESS_TYPE_TCP, record['scheme']))
    return oshv


def DiscoveryMain(Framework):
    from appilog.common.system.types.vectors import ObjectStateHolderVector
    import logger

    ip = Framework.getDestinationAttribute('ip_address')
    port = int(_param(Framework, 'ippPort', '631'))
    use_tls = _param(Framework, 'useTls', 'false').lower() == 'true'
    extra = [p.strip() for p in _param(Framework, 'extraPaths', '').split(',') if p.strip()]
    transport = JavaTransport(int(_param(Framework, 'connectTimeoutMs', '1500')),
                              int(_param(Framework, 'timeoutMs', '5000')))
    ci_type = _param(Framework, 'printerCiType', 'netprinter')
    report_endpoint = _param(Framework, 'reportServiceEndpoint', 'true').lower() != 'false'

    try:
        record, _attrs, open_ports, note = probe_host(ip, transport, port, use_tls, DEFAULT_PATHS + extra)
    except Exception as e:
        logger.debugException('IPP probe failed for %s' % ip)
        Framework.reportWarning('IPP probe failed: %s' % e)
        return ObjectStateHolderVector()

    if record is None:
        logger.debug('No IPP printer at %s: %s' % (ip, note))
        # Closed port is the normal case; only surface what an operator can act on.
        if open_ports and ('auth required' in note or 'TLS required' in note or 'print server' in note):
            Framework.reportWarning('%s: %s' % (ip, note))
        return ObjectStateHolderVector()

    logger.info('IPP printer at %s: %s (sn=%s, location=%s)'
                % (ip, record['make_model'], record['serial'] or '-', record['location']))
    return build_oshv(record, ci_type, report_endpoint)
