# Invoke-PrinterDiscovery.ps1 — PowerShell port (no install needed)

This is the same credential-free IPP printer discovery as the Python
scanner in `printer_discovery/`, as one PowerShell script. It is meant to
run on the UCMDB Data Flow Probe server (or any Windows host) without
installing anything.

- **Runs on:** Windows PowerShell 5.1 (built into Windows Server 2016+ and
  Windows 10+) and PowerShell 7+.
- **Dependencies:** none. It uses only .NET classes that ship with Windows.
- **Output:** a CSV with the **same columns and values** as the Python
  version (an automated test checks this), so one UCMDB mapping works for both.
- **Safe to run:** read-only, with one anonymous HTTP POST per path tried.
  Nothing prints, no credentials are used, and nothing is written to the
  devices.

## Run it

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-PrinterDiscovery.ps1 `
    -TargetFile D:\printer_discovery\subnets.txt -Tls `
    -CsvPath D:\ucmdb_import\printers.csv -ShowMisses
```

| Parameter | Meaning |
|---|---|
| `-Target 10.1.0.0/24,10.2.3.4` | IPv4 addresses or CIDRs |
| `-TargetFile subnets.txt` | one IP or CIDR per line; `#` comments allowed |
| `-CsvPath` | CSV for UCMDB (UTF-8 **without** BOM, all fields quoted) |
| `-JsonPath` | JSON that also holds every raw IPP attribute (for troubleshooting) |
| `-Tls` | also try `ipps://` on 631 and 443 |
| `-ExtraPath /printers/X` | extra IPP paths, e.g. queues on a CUPS print server |
| `-Throttle 64` | hosts probed in parallel |
| `-ConnectTimeoutMs 1500` / `-TimeoutMs 5000` | TCP check and per-request timeouts |
| `-MaxHosts 65536` | safety cap on how many addresses one run expands to |
| `-ShowMisses` | list hosts with 631 open but no printer answer, and why |

Without `-CsvPath`/`-JsonPath`, the script writes objects to the pipeline:

```powershell
.\Invoke-PrinterDiscovery.ps1 -Target 10.10.0.0/24 | Format-Table ip, make_model, serial, location
```

**Execution policy:** the script isn't signed. Either run it with
`-ExecutionPolicy Bypass` as above, or sign it with your organisation's
code-signing certificate if policy is `AllSigned`.

## Schedule it on the probe server

Run it as a **non-admin local service account**. It only needs outbound
network access to the printer subnets on TCP 631 (and 443 with `-Tls`), plus
write access to the output folder.

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
  '-NoProfile -ExecutionPolicy Bypass -File D:\printer_discovery\Invoke-PrinterDiscovery.ps1 -TargetFile D:\printer_discovery\subnets.txt -Tls -CsvPath D:\ucmdb_import\printers.csv'
$trigger = New-ScheduledTaskTrigger -Daily -At 01:30
Register-ScheduledTask -TaskName 'Printer Discovery (IPP)' -Action $action -Trigger $trigger `
  -User 'DOMAIN\svc-prn-disc' -Password '<set by admin>'
```

Then schedule the UCMDB import job (below) to run afterwards, e.g. 03:00.

Sizing: about 64 hosts are probed at a time, and a host with nothing on 631
costs only the connect timeout. A /16 (65k addresses) with mostly empty space
takes roughly 65,536 / 64 × 1.5 s ≈ 25 min. Feed it the subnets NetBrain or
IPAM knows are in use rather than whole /8s.

## Import into UCMDB (Option A)

Use the out-of-the-box **Import from CSV** job (Data Flow Management →
Discovery Control Panel → *Integrations / Import from External Source*).
Point it at the CSV, comma delimiter, `"` quote character, and one header
line to skip. Parameter names and trigger requirements differ slightly
between UCMDB versions, so check the job's *Properties* tab. In some versions
the job is triggered on a Shell CI for the host that holds the file.

Suggested column mapping. **Confirm CI types and attribute names with the
USS CMDB team's class model** (CI Type Manager):

| CSV column | UCMDB target (suggested) | Notes |
|---|---|---|
| `ip` | IP Address CI (`name`), linked to the Node | main key for reconciliation with NetBrain |
| `make_model` | Node `discovered_model` | e.g. *HP LaserJet MFP M428fdw* |
| `manufacturer` | Node `discovered_vendor` | from the IEEE 1284 device ID (`MFG:`) |
| `serial` | Node `serial_number` | not every vendor exposes it; strong reconciliation key when present |
| `name` | Node `name` | the printer's own name |
| `location` | Node `description`, or a Location CI | free text set on the printer |
| `uuid` | custom attribute, or `description` | stable ID that survives an IP change |
| `firmware` | Node `discovered_os_version` or custom | |
| `node role` (constant) | `node_role = printer` | so the CI is classified as a printer |

Columns such as `state`, `state_reasons` and `supplies` (toner levels) change
often. They usually belong in monitoring rather than the CMDB, so leave them
unmapped unless USS wants them.

## Troubleshooting hosts that have 631 open but no record (`-ShowMisses`)

| Note | Meaning / action |
|---|---|
| `auth required` | the printer requires login even to read attributes; use another method |
| `TLS required` | re-run with `-Tls` |
| `likely print server` | CUPS or another print server; add queues with `-ExtraPath /printers/<name>` |
| `not IPP` | something else is listening on that port |

## Tests

`printer_discovery/tests/test_powershell.py` runs this script against a fake
IPP printer and requires its CSV to match the Python scanner's exactly. The
test is skipped when `pwsh` is not installed:

```bash
python -m unittest discover -s printer_discovery/tests -t .
```

The test was run on PowerShell 7.4 (Linux), including the plain and TLS
paths against a real CUPS 2.4 server. The script avoids PowerShell 7-only
syntax and uses only .NET Framework APIs, so that it also runs on Windows
PowerShell 5.1. Do one smoke test on the actual probe server before
scheduling it.
