<#
.SYNOPSIS
    Credential-free printer discovery via IPP Get-Printer-Attributes.

.DESCRIPTION
    PowerShell port of the Python printer_discovery scanner. No install needed:
    runs on Windows PowerShell 5.1 (and PowerShell 7+).

    For every host it checks TCP 631 and sends an anonymous IPP
    Get-Printer-Attributes request to the usual printer resource paths over
    ipp:// (and, with -Tls, ipps:// on 631 and 443). Read-only: nothing is
    printed or changed on the device.

    The CSV has the same columns as the Python version, so the UCMDB
    "Import from CSV" mapping is identical for both.

.EXAMPLE
    .\Invoke-PrinterDiscovery.ps1 -Target 10.10.0.0/24,10.20.5.17 -TargetFile .\subnets.txt -Tls `
        -CsvPath D:\ucmdb_import\printers.csv -ShowMisses

.EXAMPLE
    .\Invoke-PrinterDiscovery.ps1 -Target 10.10.0.0/24 | Format-Table ip, make_model, serial, location
#>
[CmdletBinding()]
param(
    # IPv4 addresses or CIDRs, e.g. 10.1.2.0/24
    [string[]]$Target = @(),
    # Files with one IP/CIDR per line ('#' comments allowed)
    [string[]]$TargetFile = @(),
    # Write found printers to this CSV (UTF-8 without BOM)
    [string]$CsvPath,
    # Write found printers, including every raw IPP attribute, to this JSON
    [string]$JsonPath,
    # Also try ipps:// on the IPP port and on 443
    [switch]$Tls,
    [int]$Port = 631,
    # Extra IPP resource paths to try after the defaults, e.g. /printers/Finance
    [string[]]$ExtraPath = @(),
    # Hosts probed in parallel
    [int]$Throttle = 64,
    [int]$ConnectTimeoutMs = 1500,
    # Per IPP request
    [int]$TimeoutMs = 5000,
    [int]$MaxHosts = 65536,
    # Log hosts that have the port open but gave no printer answer, and why
    [switch]$ShowMisses
)

$ErrorActionPreference = 'Stop'

$DefaultPaths = @('/ipp/print', '/ipp', '/', '/ipp/printer', '/printer')

$OutputFields = @(
    'ip', 'port', 'scheme', 'path', 'ipp_version', 'make_model', 'manufacturer', 'model', 'serial',
    'name', 'info', 'location', 'geo_location', 'organization', 'uuid', 'dns_sd_name', 'more_info',
    'firmware', 'state', 'state_reasons', 'color', 'supplies', 'auth_supported', 'device_id'
)

# Printers almost always present self-signed certificates and we only read
# public attributes, so certificate validation is skipped for ipps://.
# A compiled callback is used because script-block callbacks are unreliable
# inside runspaces. Kept to C# 5 so Windows PowerShell 5.1 can compile it.
if (-not ('PrnDisc.TrustAll' -as [type])) {
    Add-Type -TypeDefinition @'
namespace PrnDisc {
    public static class TrustAll {
        public static bool Accept(object sender,
            System.Security.Cryptography.X509Certificates.X509Certificate certificate,
            System.Security.Cryptography.X509Certificates.X509Chain chain,
            System.Net.Security.SslPolicyErrors errors) { return true; }
        public static readonly System.Net.Security.RemoteCertificateValidationCallback Callback = Accept;
    }
}
'@
}

# ---------------------------------------------------------------------------
# Probe functions. These are copied into every runspace, so each keeps its
# parameters in a param() block and uses no script-level variables.
# ---------------------------------------------------------------------------

function Write-IppU16 {
    param([System.IO.Stream]$Stream, [int]$Value)
    $Stream.WriteByte(($Value -shr 8) -band 0xFF)
    $Stream.WriteByte($Value -band 0xFF)
}

function Write-IppAttr {
    param([System.IO.Stream]$Stream, [int]$Tag, [string]$Name, [byte[]]$Value)
    $n = [System.Text.Encoding]::UTF8.GetBytes($Name)
    $Stream.WriteByte($Tag)
    Write-IppU16 $Stream $n.Length
    $Stream.Write($n, 0, $n.Length)
    Write-IppU16 $Stream $Value.Length
    $Stream.Write($Value, 0, $Value.Length)
}

function New-IppGetPrinterAttributes {
    param([string]$PrinterUri, [int]$RequestId = 1)
    # Attributes useful for inventory. Printers silently ignore ones they lack.
    $attributes = @(
        'printer-make-and-model', 'printer-device-id', 'printer-name', 'printer-info',
        'printer-location', 'printer-geo-location', 'printer-organization',
        'printer-organizational-unit', 'printer-uuid', 'printer-dns-sd-name', 'printer-more-info',
        'printer-uri-supported', 'printer-firmware-name', 'printer-firmware-string-version',
        'printer-state', 'printer-state-reasons', 'printer-is-accepting-jobs', 'printer-up-time',
        'color-supported', 'marker-names', 'marker-levels', 'marker-colors', 'marker-types',
        'ipp-versions-supported', 'uri-security-supported', 'uri-authentication-supported'
    )
    $u = [System.Text.Encoding]::UTF8
    $ms = New-Object System.IO.MemoryStream
    $ms.WriteByte(2); $ms.WriteByte(0)          # IPP 2.0
    Write-IppU16 $ms 0x000B                     # Get-Printer-Attributes
    $rid = [BitConverter]::GetBytes([int]$RequestId)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($rid) }
    $ms.Write($rid, 0, 4)
    $ms.WriteByte(0x01)                         # operation-attributes-tag
    Write-IppAttr $ms 0x47 'attributes-charset' $u.GetBytes('utf-8')
    Write-IppAttr $ms 0x48 'attributes-natural-language' $u.GetBytes('en')
    Write-IppAttr $ms 0x45 'printer-uri' $u.GetBytes($PrinterUri)
    Write-IppAttr $ms 0x42 'requesting-user-name' $u.GetBytes('discovery')
    for ($i = 0; $i -lt $attributes.Count; $i++) {
        # Additional values of a 1setOf carry an empty name.
        $name = ''
        if ($i -eq 0) { $name = 'requested-attributes' }
        Write-IppAttr $ms 0x44 $name $u.GetBytes($attributes[$i])
    }
    $ms.WriteByte(0x03)                         # end-of-attributes-tag
    return , $ms.ToArray()
}

function Read-IppU16 {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset + 2 -gt $Bytes.Length) { throw 'malformed IPP response: truncated' }
    return ([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1]
}

function Read-IppI32 {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset + 4 -gt $Bytes.Length) { throw 'malformed IPP response: truncated' }
    $t = New-Object byte[] 4
    [Array]::Copy($Bytes, $Offset, $t, 0, 4)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($t) }
    return [BitConverter]::ToInt32($t, 0)
}

function ConvertFrom-IppValue {
    param([int]$Tag, [byte[]]$Bytes, [int]$Offset, [int]$Length)
    $u = [System.Text.Encoding]::UTF8
    if (($Tag -eq 0x21 -or $Tag -eq 0x23) -and $Length -eq 4) { return (Read-IppI32 $Bytes $Offset) }   # integer, enum
    if ($Tag -eq 0x22 -and $Length -eq 1) { return ($Bytes[$Offset] -ne 0) }                            # boolean
    if (($Tag -ge 0x41 -and $Tag -le 0x49 -and $Tag -ne 0x43) -or $Tag -eq 0x30) {                      # strings, octetString
        return $u.GetString($Bytes, $Offset, $Length)
    }
    if (($Tag -eq 0x35 -or $Tag -eq 0x36) -and $Length -ge 4) {                                         # text/nameWithLanguage
        $ll = Read-IppU16 $Bytes $Offset
        $tl = Read-IppU16 $Bytes ($Offset + 2 + $ll)
        return $u.GetString($Bytes, $Offset + 4 + $ll, $tl)
    }
    if ($Tag -eq 0x32 -and $Length -eq 9) {                                                             # resolution
        $unit = 'dpcm'
        if ($Bytes[$Offset + 8] -eq 3) { $unit = 'dpi' }
        return '{0}x{1}{2}' -f (Read-IppI32 $Bytes $Offset), (Read-IppI32 $Bytes ($Offset + 4)), $unit
    }
    if ($Tag -eq 0x33 -and $Length -eq 8) {                                                             # rangeOfInteger
        return '{0}-{1}' -f (Read-IppI32 $Bytes $Offset), (Read-IppI32 $Bytes ($Offset + 4))
    }
    if ($Length -eq 0) { return '' }
    return [BitConverter]::ToString($Bytes, $Offset, $Length).Replace('-', '').ToLowerInvariant()
}

function Read-IppResponse {
    # Parses into a flat name -> values dictionary. Collection values are skipped.
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 8) { throw "IPP response too short ($($Bytes.Length) bytes)" }
    $resp = @{
        Version    = '{0}.{1}' -f $Bytes[0], $Bytes[1]
        Status     = Read-IppU16 $Bytes 2
        RequestId  = Read-IppI32 $Bytes 4
        Attributes = New-Object System.Collections.Specialized.OrderedDictionary
    }
    $pos = 8
    $current = $null
    $depth = 0   # >0 while inside a collection, whose members we skip
    while ($pos -lt $Bytes.Length) {
        $tag = [int]$Bytes[$pos]; $pos++
        if ($tag -eq 0x03) { break }
        if ($tag -lt 0x10) { $current = $null; continue }   # group delimiter
        $nlen = Read-IppU16 $Bytes $pos; $pos += 2
        if ($pos + $nlen -gt $Bytes.Length) { throw 'malformed IPP response: truncated name' }
        $name = [System.Text.Encoding]::UTF8.GetString($Bytes, $pos, $nlen); $pos += $nlen
        $vlen = Read-IppU16 $Bytes $pos; $pos += 2
        if ($pos + $vlen -gt $Bytes.Length) { throw 'malformed IPP response: truncated value' }
        $voff = $pos; $pos += $vlen

        if ($tag -eq 0x34) { $depth++; if ($depth -eq 1 -and $name) { $current = $name }; continue }
        if ($tag -eq 0x37) { if ($depth -gt 0) { $depth-- }; continue }
        if ($depth -gt 0) { continue }
        if ($name) { $current = $name }
        if ($null -eq $current) { continue }
        if (-not $resp.Attributes.Contains($current)) {
            $resp.Attributes[$current] = New-Object System.Collections.ArrayList
        }
        [void]$resp.Attributes[$current].Add((ConvertFrom-IppValue $tag $Bytes $voff $vlen))
    }
    return $resp
}

function Find-HttpHeaderEnd {
    param([byte[]]$Bytes)
    for ($i = 0; $i -le $Bytes.Length - 4; $i++) {
        if ($Bytes[$i] -eq 13 -and $Bytes[$i + 1] -eq 10 -and $Bytes[$i + 2] -eq 13 -and $Bytes[$i + 3] -eq 10) { return $i }
    }
    return -1
}

function ConvertFrom-HttpChunked {
    param([byte[]]$Bytes, [int]$Start)
    $out = New-Object System.IO.MemoryStream
    $pos = $Start
    while ($pos -lt $Bytes.Length) {
        $eol = $pos
        while ($eol + 1 -lt $Bytes.Length -and -not ($Bytes[$eol] -eq 13 -and $Bytes[$eol + 1] -eq 10)) { $eol++ }
        $sizeText = [System.Text.Encoding]::ASCII.GetString($Bytes, $pos, $eol - $pos).Split(';')[0].Trim()
        if (-not $sizeText) { break }
        $size = [Convert]::ToInt32($sizeText, 16)
        if ($size -eq 0) { break }
        $pos = $eol + 2
        if ($pos + $size -gt $Bytes.Length) { throw 'truncated HTTP chunk' }
        $out.Write($Bytes, $pos, $size)
        $pos += $size + 2
    }
    return , $out.ToArray()
}

function Invoke-IppPost {
    # One IPP request over HTTP/1.1. Returns @{ HttpStatus; Body }.
    param([string]$Ip, [int]$Port, [string]$Path, [byte[]]$Payload, [bool]$UseTls,
          [int]$ConnectTimeoutMs, [int]$TimeoutMs)
    $limit = 1MB
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($Ip, $Port).Wait($ConnectTimeoutMs)) { throw 'connect timeout' }
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs
        if ($UseTls) {
            $ssl = New-Object System.Net.Security.SslStream($stream, $false, [PrnDisc.TrustAll]::Callback)
            $protocols = [System.Security.Authentication.SslProtocols]'Tls12, Tls11, Tls'
            $ssl.AuthenticateAsClient($Ip, $null, $protocols, $false)
            $stream = $ssl
        }
        $head = "POST $Path HTTP/1.1`r`nHost: ${Ip}:$Port`r`nContent-Type: application/ipp`r`n" +
                "Content-Length: $($Payload.Length)`r`nConnection: close`r`n`r`n"
        $hb = [System.Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($hb, 0, $hb.Length)
        $stream.Write($Payload, 0, $Payload.Length)
        $stream.Flush()

        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 65536
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $headerEnd = -1; $contentLength = -1; $chunked = $false
        while ($true) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
            if ($ms.Length -gt $limit) { throw 'response too large' }
            if ($sw.ElapsedMilliseconds -gt $TimeoutMs) { throw 'timeout' }
            # Stop as soon as the body is complete, in case the server ignores Connection: close.
            $all = $ms.ToArray()
            if ($headerEnd -lt 0) {
                $headerEnd = Find-HttpHeaderEnd $all
                if ($headerEnd -ge 0) {
                    $headText = [System.Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
                    if ($headText -match '(?im)^content-length:\s*(\d+)') { $contentLength = [int]$Matches[1] }
                    if ($headText -match '(?im)^transfer-encoding:\s*chunked') { $chunked = $true }
                }
            }
            if ($headerEnd -ge 0) {
                if ($contentLength -ge 0 -and $all.Length -ge $headerEnd + 4 + $contentLength) { break }
                if ($chunked -and $all.Length -ge 5 -and $all[$all.Length - 5] -eq 48 -and
                    $all[$all.Length - 4] -eq 13 -and $all[$all.Length - 3] -eq 10 -and
                    $all[$all.Length - 2] -eq 13 -and $all[$all.Length - 1] -eq 10) { break }
            }
        }
        $all = $ms.ToArray()
        $headerEnd = Find-HttpHeaderEnd $all
        if ($headerEnd -lt 0) { throw 'not an HTTP response' }
        $headText = [System.Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
        if ($headText -notmatch '^HTTP/\d\.\d\s+(\d{3})') { throw 'not an HTTP response' }
        $status = [int]$Matches[1]
        if ($status -ne 200) { return @{ HttpStatus = $status; Body = $null } }
        if ($headText -match '(?im)^transfer-encoding:\s*chunked') {
            $body = ConvertFrom-HttpChunked $all ($headerEnd + 4)
        } else {
            $len = $all.Length - ($headerEnd + 4)
            if ($headText -match '(?im)^content-length:\s*(\d+)') { $len = [Math]::Min($len, [int]$Matches[1]) }
            $body = New-Object byte[] $len
            [Array]::Copy($all, $headerEnd + 4, $body, 0, $len)
        }
        return @{ HttpStatus = 200; Body = $body }
    } finally {
        $client.Close()
    }
}

function Test-TcpPort {
    param([string]$Ip, [int]$Port, [int]$TimeoutMs)
    $c = New-Object System.Net.Sockets.TcpClient
    try { return $c.ConnectAsync($Ip, $Port).Wait($TimeoutMs) }
    catch { return $false }
    finally { $c.Close() }
}

function ConvertTo-PrinterRecord {
    param([string]$Ip, [int]$Port, [string]$Scheme, [string]$Path, [hashtable]$Resp)
    $a = $Resp.Attributes
    $first = { param($n) if ($a.Contains($n) -and $a[$n].Count -gt 0) { $a[$n][0] } else { $null } }
    $str = { param($v) if ($null -eq $v) { '' } else { "$v" } }
    $list = { param($n) if ($a.Contains($n)) { @($a[$n]) } else { @() } }
    $join = { param($vals) (@($vals | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join ', ') }

    $devId = & $str (& $first 'printer-device-id')
    $did = @{}
    foreach ($part in $devId.Split(';')) {
        $kv = $part.Split(':', 2)
        if ($kv.Count -eq 2) { $did[$kv[0].Trim().ToUpperInvariant()] = $kv[1].Trim() }
    }
    $pick = { param([string[]]$keys) foreach ($k in $keys) { if ($did[$k]) { return $did[$k] } }; '' }

    $fwNames = @(& $list 'printer-firmware-name')
    $fwVers = @(& $list 'printer-firmware-string-version')
    $fw = for ($i = 0; $i -lt [Math]::Max($fwNames.Count, $fwVers.Count); $i++) {
        $n = ''; $v = ''
        if ($i -lt $fwNames.Count) { $n = "$($fwNames[$i])" }
        if ($i -lt $fwVers.Count) { $v = "$($fwVers[$i])" }
        "$n $v".Trim()
    }

    $mNames = @(& $list 'marker-names')
    $mLevels = @(& $list 'marker-levels')
    $supplies = for ($i = 0; $i -lt [Math]::Min($mNames.Count, $mLevels.Count); $i++) {
        $lvl = $mLevels[$i]
        if ($lvl -is [int] -and $lvl -ge 0) { "$($mNames[$i])=$lvl%" } else { "$($mNames[$i])=?" }
    }

    $stateVal = & $first 'printer-state'
    $states = @{ 3 = 'idle'; 4 = 'processing'; 5 = 'stopped' }
    $state = & $str $stateVal
    if ($stateVal -is [int] -and $states.ContainsKey($stateVal)) { $state = $states[$stateVal] }

    $colorVal = & $first 'color-supported'
    $color = ''
    if ($colorVal -is [bool]) { if ($colorVal) { $color = 'yes' } else { $color = 'no' } }

    $rec = [pscustomobject][ordered]@{
        ip             = $Ip
        port           = $Port
        scheme         = $Scheme
        path           = $Path
        ipp_version    = $Resp.Version
        make_model     = & $str (& $first 'printer-make-and-model')
        manufacturer   = & $pick @('MFG', 'MANUFACTURER')
        model          = & $pick @('MDL', 'MODEL')
        serial         = & $pick @('SN', 'SERN', 'SERIALNUMBER')
        name           = & $str (& $first 'printer-name')
        info           = & $str (& $first 'printer-info')
        location       = & $str (& $first 'printer-location')
        geo_location   = & $str (& $first 'printer-geo-location')
        organization   = & $join (@(& $list 'printer-organization') + @(& $list 'printer-organizational-unit'))
        uuid           = & $str (& $first 'printer-uuid')
        dns_sd_name    = & $str (& $first 'printer-dns-sd-name')
        more_info      = & $str (& $first 'printer-more-info')
        firmware       = & $join $fw
        state          = $state
        state_reasons  = & $join (& $list 'printer-state-reasons')
        color          = $color
        supplies       = & $join $supplies
        auth_supported = & $join (& $list 'uri-authentication-supported')
        device_id      = $devId
    }
    return $rec
}

function Invoke-PrinterProbe {
    param([string]$Ip, [int]$Port, [string[]]$Paths, [bool]$UseTls, [int]$ConnectTimeoutMs, [int]$TimeoutMs)
    $ErrorActionPreference = 'Stop'
    $result = [pscustomobject]@{ Ip = $Ip; Record = $null; Raw = $null; OpenPorts = @(); Note = '' }

    # (port, tls) combinations to try in order.
    $attempts = @(, @($Port, $false))
    if ($UseTls) { $attempts += , @($Port, $true); $attempts += , @(443, $true) }

    $checked = @{}
    $notes = New-Object System.Collections.Generic.List[string]
    $sawIppNotFound = $false
    foreach ($att in $attempts) {
        $p = [int]$att[0]; $tls = [bool]$att[1]
        if (-not $checked.ContainsKey($p)) {
            $checked[$p] = Test-TcpPort $Ip $p $ConnectTimeoutMs
            if ($checked[$p]) { $result.OpenPorts += $p }
        }
        if (-not $checked[$p]) { continue }
        $scheme = 'ipp'
        if ($tls) { $scheme = 'ipps' }
        foreach ($path in $Paths) {
            $uri = "${scheme}://${Ip}:$p$path"
            try {
                $http = Invoke-IppPost $Ip $p $path (New-IppGetPrinterAttributes $uri) $tls $ConnectTimeoutMs $TimeoutMs
            } catch {
                $notes.Add("${scheme}:$p not IPP"); break   # don't hammer a port that doesn't speak IPP
            }
            if ($http.HttpStatus -eq 401 -or $http.HttpStatus -eq 403) { $notes.Add("${scheme}:$p auth required"); break }
            if ($http.HttpStatus -eq 426) { $notes.Add("${scheme}:$p TLS required"); break }
            if ($http.HttpStatus -ne 200) { continue }   # 404/400 etc.: try next path
            try {
                $resp = Read-IppResponse $http.Body
            } catch {
                $notes.Add("${scheme}:$p not IPP"); break
            }
            if ($resp.Status -lt 0x0100) {   # successful-ok*
                $result.Record = ConvertTo-PrinterRecord $Ip $p $scheme $path $resp
                $result.Raw = $resp.Attributes
                return $result
            }
            if ($resp.Status -eq 0x0400 -or $resp.Status -eq 0x0406) { $sawIppNotFound = $true; continue }
            $notes.Add(('{0}:{1} IPP status 0x{2:x4}' -f $scheme, $p, $resp.Status)); break
        }
    }
    if ($sawIppNotFound) {
        # Speaks IPP but has no printer at the usual paths: typically a CUPS or
        # other print server whose queues live under /printers/<name>.
        $notes.Add('IPP server without printer at common paths (likely print server)')
    }
    $result.Note = (@($notes | Select-Object -Unique) -join '; ')
    if (-not $result.Note) {
        if ($result.OpenPorts.Count -eq 0) { $result.Note = 'no IPP port open' } else { $result.Note = 'no IPP path answered' }
    }
    return $result
}

$ProbeFunctions = @(
    'Write-IppU16', 'Write-IppAttr', 'New-IppGetPrinterAttributes', 'Read-IppU16', 'Read-IppI32',
    'ConvertFrom-IppValue', 'Read-IppResponse', 'Find-HttpHeaderEnd', 'ConvertFrom-HttpChunked',
    'Invoke-IppPost', 'Test-TcpPort', 'ConvertTo-PrinterRecord', 'Invoke-PrinterProbe'
)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Expand-Targets {
    # Expand IPv4 addresses / CIDRs into a de-duplicated host list.
    param([string[]]$Specs, [int]$Max)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $hosts = New-Object System.Collections.Generic.List[string]
    foreach ($raw in $Specs) {
        $spec = ($raw -split '#', 2)[0].Trim()
        if (-not $spec) { continue }
        $parts = $spec.Split('/')
        $ip = [System.Net.IPAddress]::Parse($parts[0])
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw "only IPv4 is supported: $spec" }
        $prefix = 32
        if ($parts.Count -gt 1) { $prefix = [int]$parts[1] }
        if ($prefix -lt 0 -or $prefix -gt 32) { throw "bad prefix length: $spec" }
        $b = $ip.GetAddressBytes()
        $val = [int64]$b[0] * 16777216 + [int64]$b[1] * 65536 + [int64]$b[2] * 256 + [int64]$b[3]
        $size = [int64][Math]::Pow(2, 32 - $prefix)
        $net = $val - ($val % $size)
        if ($prefix -ge 31) { $lo = $net; $hi = $net + $size - 1 } else { $lo = $net + 1; $hi = $net + $size - 2 }
        for ($v = $lo; $v -le $hi; $v++) {
            $s = '{0}.{1}.{2}.{3}' -f (($v -shr 24) -band 255), (($v -shr 16) -band 255), (($v -shr 8) -band 255), ($v -band 255)
            if ($seen.Add($s)) {
                $hosts.Add($s)
                if ($hosts.Count -gt $Max) { throw "more than $Max hosts; raise -MaxHosts if intended" }
            }
        }
    }
    return , $hosts
}

$specs = @($Target)
foreach ($f in $TargetFile) { $specs += @(Get-Content -LiteralPath $f) }
if ($specs.Count -eq 0) { throw 'no targets given (use -Target and/or -TargetFile)' }
$hosts = Expand-Targets $specs $MaxHosts
$paths = @($DefaultPaths) + @($ExtraPath)

Write-Host "probing $($hosts.Count) hosts ..."

# Each runspace gets the probe functions once, then only receives a host per job.
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
foreach ($fn in $ProbeFunctions) {
    $def = (Get-Item "function:$fn").ScriptBlock.ToString()
    $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $def)))
}
$pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Throttle), $iss, $Host)
$pool.Open()

$records = New-Object System.Collections.Generic.List[object]
$raws = New-Object System.Collections.Generic.List[object]
$running = New-Object System.Collections.Generic.List[object]
$next = 0
try {
    while ($next -lt $hosts.Count -or $running.Count -gt 0) {
        # Sliding window keeps memory flat on large sweeps.
        while ($running.Count -lt $Throttle * 2 -and $next -lt $hosts.Count) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddCommand('Invoke-PrinterProbe').AddParameters(@{
                Ip = $hosts[$next]; Port = $Port; Paths = $paths; UseTls = [bool]$Tls
                ConnectTimeoutMs = $ConnectTimeoutMs; TimeoutMs = $TimeoutMs
            })
            $running.Add([pscustomobject]@{ Ip = $hosts[$next]; PS = $ps; Handle = $ps.BeginInvoke() })
            $next++
        }
        $done = @($running | Where-Object { $_.Handle.IsCompleted })
        if ($done.Count -eq 0) { Start-Sleep -Milliseconds 50; continue }
        foreach ($job in $done) {
            [void]$running.Remove($job)
            try {
                $r = @($job.PS.EndInvoke($job.Handle))[0]
            } catch {
                $r = [pscustomobject]@{ Ip = $job.Ip; Record = $null; Raw = $null; OpenPorts = @(); Note = "error: $($_.Exception.Message)" }
            } finally {
                $job.PS.Dispose()
            }
            if ($null -eq $r) { continue }
            if ($r.Record) {
                $rec = $r.Record
                $label = $rec.make_model
                if (-not $label) { $label = $rec.model }
                if (-not $label) { $label = '?' }
                $sn = $rec.serial
                if (-not $sn) { $sn = '-' }
                Write-Host ("[+] {0,-15} {1}  loc='{2}'  sn={3}" -f $r.Ip, $label, $rec.location, $sn) -ForegroundColor Green
                $records.Add($rec)
                $raws.Add($r.Raw)
            } elseif ($ShowMisses -and @($r.OpenPorts).Count -gt 0) {
                Write-Host ("[-] {0,-15} ports={1} {2}" -f $r.Ip, (@($r.OpenPorts) -join ','), $r.Note) -ForegroundColor Yellow
            }
        }
    }
} finally {
    foreach ($job in $running) { $job.PS.Stop(); $job.PS.Dispose() }
    $pool.Close(); $pool.Dispose()
}

Write-Host "done: $($records.Count) printers found out of $($hosts.Count) hosts"

# Stable output order (by IP) regardless of completion order.
$order = @(0..($records.Count - 1) | Where-Object { $records.Count -gt 0 } |
    Sort-Object { [version]$records[$_].ip })

if ($CsvPath) {
    # UTF-8 without BOM: a BOM would corrupt the first header in many CSV importers.
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((($OutputFields | ForEach-Object { '"' + $_ + '"' }) -join ','))
    foreach ($i in $order) {
        $rec = $records[$i]
        $lines.Add((($OutputFields | ForEach-Object { '"' + ("$($rec.$_)" -replace '"', '""') + '"' }) -join ','))
    }
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)
    [System.IO.File]::WriteAllLines($full, $lines, (New-Object System.Text.UTF8Encoding($false)))
}
if ($JsonPath) {
    $items = foreach ($i in $order) {
        $o = [ordered]@{}
        foreach ($f in $OutputFields) { $o[$f] = $records[$i].$f }
        $o['raw'] = $raws[$i]
        [pscustomobject]$o
    }
    $json = ConvertTo-Json -InputObject @($items) -Depth 6
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JsonPath)
    [System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
}
if (-not $CsvPath -and -not $JsonPath) {
    foreach ($i in $order) { $records[$i] }
}
