"""Run the UCMDB adapter's probe logic under plain Jython (outside UCMDB).

Useful to test the Java transport from any machine with Java:
    java -jar jython-standalone-2.7.x.jar jython_probe.py <ip> [port] [--tls] [--path /extra]
Prints the result as JSON.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))
import printer_by_ipp  # noqa: E402

args = sys.argv[1:]
use_tls = '--tls' in args
extra = []
positional = []
i = 0
while i < len(args):
    if args[i] == '--tls':
        pass
    elif args[i] == '--path':
        i += 1
        extra.append(args[i])
    else:
        positional.append(args[i])
    i += 1
ip = positional[0]
port = int(positional[1]) if len(positional) > 1 else 631

record, attrs, open_ports, note = printer_by_ipp.probe_host(
    ip, printer_by_ipp.JavaTransport(1500, 5000), port, use_tls, printer_by_ipp.DEFAULT_PATHS + extra)
print(json.dumps({'record': record, 'open_ports': open_ports, 'note': note}))
