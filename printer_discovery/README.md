# printer_discovery — credential-free printer discovery (IPP)

Complements NetBrain/SNMP inventory. NetBrain sees printers from the network
side (ARP/MAC/CDP). This asks the device itself, anonymously, what it is.

**Method 1 (this module): IPP `Get-Printer-Attributes`** — TCP 631 (and
optionally IPPS on 631/443). The IPP standard lets anyone read these
attributes without logging in, and almost every network printer since
about 2010 answers. It is unicast, so it works across routed subnets from
a single scanner host.

Python 3.9+, standard library only.

## Usage

```bash
# subnets on the command line or in a file (one IP/CIDR per line, # comments ok)
python -m printer_discovery 10.10.0.0/24 10.20.5.17 -f subnets.txt \
    --tls --csv printers.csv --json printers.json --show-misses
```

| Option | Meaning |
|---|---|
| `--tls` | also try `ipps://` on 631 and 443 (for hardened fleets) |
| `--path /printers/X` | extra IPP resource path(s), e.g. for CUPS print servers |
| `--concurrency 256` | parallel hosts |
| `--connect-timeout 1.5` / `--timeout 5` | TCP check / per-request timeouts (seconds) |
| `--show-misses` | log hosts that have 631 open but gave no printer answer, and why |

## Output fields

`ip, port, scheme, path, ipp_version, make_model, manufacturer, model, serial,
name, info, location, geo_location, organization, uuid, dns_sd_name,
more_info, firmware, state, state_reasons, color, supplies, auth_supported,
device_id`

- `manufacturer` / `model` / `serial` come from the IEEE 1284 `printer-device-id`
  (`MFG:`, `MDL:`, `SN:`). Not every vendor includes `SN:`.
- `supplies` is e.g. `Black Cartridge=12%` (from `marker-names` and `marker-levels`).
- The JSON output also has `raw`, which holds every attribute the printer returned.

Merge with NetBrain on `ip`. NetBrain adds switch, port and VLAN; this adds
model, serial, location and status.

## Why a host can have 631 open but no record (`--show-misses`)

- `auth required`: the printer requires login even to read attributes
  (uncommon). Use another method for it.
- `TLS required`: re-run with `--tls`.
- `likely print server`: a CUPS or print server whose queues live under
  `/printers/<name>`. Add them with `--path`.
- `not IPP`: something other than IPP is listening on that port.

## Operational notes

- Read-only: one HTTP POST per path tried. Nothing prints and nothing is changed.
- Have security approve the sweep and whitelist the scanner host before
  running it, so IDS/NDR alerts don't come as a surprise.
- For IPPS, the scanner deliberately skips certificate checks, because
  printers almost always use self-signed certificates.

## Tests

```bash
python -m unittest discover -s printer_discovery/tests -t .
```

Also checked by hand against a real CUPS 2.4 server, over both `ipp://` and `ipps://`.

## Next methods (planned)

HTTP/TLS-certificate fingerprinting, mDNS/DNS-SD and WS-Discovery site
agents, DHCP fingerprint and MAC vendor (OUI) enrichment.
