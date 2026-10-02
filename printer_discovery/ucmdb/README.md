# UCMDB adapter: Printer by IPP (UI-only deployment)

A native UCMDB discovery adapter for credential-free printer discovery. You
deploy it entirely from the **UCMDB UI**, with no login to the probe
server. The probe already ships Jython and Java, so nothing gets installed.

| File | Purpose |
|---|---|
| `printer_by_ipp.py` | the adapter script you paste into UCMDB |
| `jython_probe.py` | optional: run the same probe logic with plain Jython outside UCMDB |

**What it does:** for each triggered IP address, the probe connects to TCP 631
and sends an anonymous IPP *Get-Printer-Attributes* request. If the device
answers as a printer, the job reports:

| CI | Attributes |
|---|---|
| printer Node (CI type from `printerCiType`, default `netprinter`) | `discovered_vendor`, `discovered_model`, `serial_number`, `discovered_os_version` (firmware), `description` (make/model, IPP name, location, UUID), `node_role = printer` |
| IpAddress, linked to the Node by *containment* | |
| IpServiceEndpoint tcp/631 (`ipp` or `ipps`) | can be turned off with `reportServiceEndpoint=false` |

It never prints, changes anything or uses credentials. Hosts with nothing on 631
finish silently. Only things an operator can act on appear as job warnings
(*auth required*, *TLS required*, *likely print server*).

**Tested against:** a real CUPS 2.4 IPP server (plain and TLS) and a fake HP
printer, using Jython 2.7.4 on Java 21 with the same Java socket code the
probe uses. The UCMDB API calls (`modeling.*`, `Framework.*`) were tested
against stand-ins, **not on a real UCMDB**, so do the pilot in step 5 first.

---

## Before you start

- **Rights:** your UCMDB role needs Adapter Management and Discovery Control
  Panel rights (and Modeling Studio rights for the trigger query). If
  *Adapter Management* lets you create new resources, you have them.
- **Change approval:** this puts new code on the probe. Attach
  `printer_by_ipp.py` to the change request; it is short and commented.
- **Printer CI type:** in *Modeling → CI Type Manager*, find the CI type USS uses
  for network printers (often *Net Printer*, internal name `netprinter`).
  Note the **internal name** for the `printerCiType` parameter. If there
  isn't one, use `node`.

Menu names below are as of recent UCMDB versions. If 26.2 labels something
differently, the step is the same.

## 1. Create the script (Adapter Management)

1. **Data Flow Management → Adapter Management.**
2. In the *Resources* pane, choose **Create new resource → New Jython script**.
3. Name it `printer_by_ipp`, and create or choose a package such as
   **`PrinterDiscoveryIPP`**, so all the parts can be exported together later.
4. Paste the full contents of `printer_by_ipp.py` and **Save**.

## 2. Create the adapter

1. **Create new resource → New adapter → Discovery adapter**, named
   `Printer_by_IPP`, in the same package.
2. **Adapter Definition** tab:
   - **Input CI Type:** `IpAddress` (`ip_address`)
   - **Required Protocols:** *none* (this is what makes it credential-free)
   - **Triggered CI data:** add `ip_address` = `${SOURCE.name}`
   - **Discovered CITs:** your printer CI type (e.g. `netprinter`),
     `ip_address`, `containment`, `ip_service_endpoint`, `composition`
   - **Used Scripts:** `printer_by_ipp.py`
   - **Global Configuration Files:** none needed
3. **Adapter Parameters.** All are optional; add any you want to change:

   | Parameter | Default | Meaning |
   |---|---|---|
   | `printerCiType` | `netprinter` | CI type for the printer node (from *Before you start*) |
   | `ippPort` | `631` | IPP port |
   | `useTls` | `false` | `true` also tries `ipps://` on 631 and 443 |
   | `extraPaths` | *(empty)* | comma-separated extra IPP paths, e.g. `/printers/Finance` |
   | `connectTimeoutMs` | `1500` | TCP connect timeout |
   | `timeoutMs` | `5000` | per-request timeout |
   | `reportServiceEndpoint` | `true` | `false` reports no tcp/631 endpoint CI |

4. **Adapter Configuration** tab: during the pilot, set **Create communication
   logs** to *Always* (or *On failure*), so you can see each run from the UI.
5. **Save.**

## 3. Create the trigger query (Modeling Studio)

Create a query, e.g. `ip_for_printer_by_ipp`, with an **IpAddress** node.
Narrow it down so you don't trigger every IP in the CMDB:
- IPs in the printer/office VLAN subnets (condition on IP address or
  `ip_probename`/probe range), or
- IPs linked to Nodes NetBrain or the nmap job already marked as printers,
  to enrich them, or
- IPs whose Node has no discovered OS, i.e. unknown devices.

## 4. Create the job (Discovery Control Panel)

1. **Data Flow Management → Discovery Control Panel**, *Discovery Modules/Jobs*.
2. Create a module, e.g. **Printer Discovery**, and in it a **new job** from the
   `Printer_by_IPP` adapter.
3. **Trigger Queries:** add `ip_for_printer_by_ipp`. Leave it empty for the pilot
   (step 5).
4. **Scheduler:** e.g. daily or weekly outside office hours.

## 5. Pilot on a few known printers

1. In the job's **Details**, use the option to **add trigger CIs manually** and
   add 3–5 IP addresses of printers you know (mixed vendors if possible),
   plus one non-printer IP.
2. **Activate** the job and watch **Discovery Progress**.
3. Check the results:
   - **Discovered CIs / Results:** each printer should give one Node, one IP,
     a containment link and one endpoint.
   - **Communication log / probe log:** lines like
     `IPP printer at 10.x.x.x: <model> (sn=..., location=...)`.
   - **Warnings:** expect none for the printers, and none for the non-printer
     IP (closed port finishes silently).
4. Open a printer CI in **IT Universe** and check vendor, model, serial and
   description, and that it **merged with the existing NetBrain CI** for that
   IP instead of creating a duplicate.

If the job fails with an error naming an attribute or CI type, the USS class
model differs. Change `printerCiType`, or tell me the error text and I'll
adjust the script.

## 6. Roll out

- Add the trigger query, set the schedule, and switch communication logs back
  to *Never* or *On failure*.
- To move this to another UCMDB (e.g. test → prod), use **Administration →
  Package Manager → Export** on the `PrinterDiscoveryIPP` package and deploy
  that zip on the target. UCMDB builds the package in the right format for
  your version.

## Warnings you may see

| Warning | Meaning / action |
|---|---|
| `auth required` | printer requires login even to read attributes; use another method for it |
| `TLS required` | set `useTls=true` |
| `likely print server` | CUPS or another print server; add its queue paths to `extraPaths` |
| `IPP probe failed: ...` | unexpected error; check the communication log and send it to me |

## Testing outside UCMDB (optional)

On any machine with Java (no UCMDB needed):

```bash
java -jar jython-standalone-2.7.4.jar jython_probe.py 10.1.2.3 [631] [--tls] [--path /extra]
```

The repo's tests (`python -m unittest discover -s printer_discovery/tests -t .`)
check that the adapter's results match the Python and PowerShell scanners.
Set `JYTHON_JAR=/path/to/jython-standalone-2.7.x.jar` to also test the
Java-socket transport.
