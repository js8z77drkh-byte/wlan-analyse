#Requires -Version 5.1
<#
.SYNOPSIS
    Finds what is slowing down the Wi-Fi on this Windows PC.

.DESCRIPTION
    Runs a set of read-only checks and writes a report:
      - Wi-Fi link: signal, band, channel, Wi-Fi standard, link rate, security
      - Neighbouring networks: channel congestion, best free channel
      - Latency / jitter / packet loss to the router vs. to the internet
      - Internet download speed and latency under load (bufferbloat)
      - DNS response time
      - Wi-Fi adapter: driver age, power saving, preferred band, channel width
      - Devices on the network, VPNs, programs with many open connections
      - Router identification (model from the admin page title, no login)

    Nothing is changed on the PC or the router.

.PARAMETER NoSpeedTest
    Skip the download speed test (contacts speed.cloudflare.com).

.PARAMETER NoSweep
    Do not ping every address in the local /24 network to find devices.

.PARAMETER OutputDir
    Where to write the report. Default: a report-<timestamp> folder next to this script.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\wlan-analyse.ps1
#>
[CmdletBinding()]
param(
    [switch]$NoSpeedTest,
    [switch]$NoSweep,
    [int]$GatewayPings = 100,
    [string]$OutputDir
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
Set-StrictMode -Off

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutputDir) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputDir = Join-Path $base "report-$stamp"
}
$RawDir = Join-Path $OutputDir 'raw'
New-Item -ItemType Directory -Force -Path $RawDir | Out-Null

$Findings = New-Object System.Collections.Generic.List[object]
$Data     = [ordered]@{ Timestamp = (Get-Date).ToString('s'); Computer = $env:COMPUTERNAME }
$Inv      = [Globalization.CultureInfo]::InvariantCulture

# ---------------------------------------------------------------- helpers

function Write-Step([string]$Message) { Write-Host "`n== $Message" -ForegroundColor Cyan }

function Add-Finding {
    param(
        [ValidateSet('High', 'Medium', 'Low', 'Info', 'OK')][string]$Severity,
        [string]$Area, [string]$Finding, [string]$Fix = ''
    )
    $Findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Finding = $Finding; Fix = $Fix })
}

function Save-Raw([string]$Name, $Content) {
    $Content | Out-File -FilePath (Join-Path $RawDir "$Name.txt") -Encoding utf8 -Width 300
}

function ConvertTo-Num($Text) {
    if ($null -eq $Text) { return $null }
    $m = [regex]::Match([string]$Text, '-?\d+([.,]\d+)?')
    if (-not $m.Success) { return $null }
    return [double]::Parse(($m.Value -replace ',', '.'), $Inv)
}

# netsh prints "   Key   : Value". Keys are localized, so callers match English and German names.
function Get-KeyValues([string[]]$Lines) {
    foreach ($l in $Lines) {
        if ($l -match '^\s*([^:]+?)\s*:\s(.*)$') {
            [pscustomobject]@{ Key = $Matches[1].Trim(); Value = $Matches[2].Trim() }
        }
    }
}

function Get-Field($Kv, [string]$Pattern) {
    ($Kv | Where-Object { $_.Key -match $Pattern } | Select-Object -First 1).Value
}

function Get-BandName($BandText, $Channel) {
    if ($BandText -match '2[.,]4') { return '2.4' }
    if ($BandText -match '^\s*6')  { return '6' }
    if ($BandText -match '^\s*5')  { return '5' }
    if ($Channel -and $Channel -le 14) { return '2.4' }
    if ($Channel) { return '5' }
    return $null
}

function Get-Block80($Channel) {
    $c = [int]$Channel
    if ($c -ge 36  -and $c -le 48)  { return '36-48' }
    if ($c -ge 52  -and $c -le 64)  { return '52-64 (DFS)' }
    if ($c -ge 100 -and $c -le 112) { return '100-112 (DFS)' }
    if ($c -ge 116 -and $c -le 128) { return '116-128 (DFS)' }
    if ($c -ge 132 -and $c -le 144) { return '132-144 (DFS)' }
    if ($c -ge 149 -and $c -le 161) { return '149-161' }
    return "ch$c"
}

# Same physical router: radios/guest networks usually differ only in the first or last MAC octet.
function Test-SameDevice([string]$A, [string]$B) {
    if (-not $A -or -not $B) { return $false }
    $pa = $A.ToLower() -split '[:-]'; $pb = $B.ToLower() -split '[:-]'
    if ($pa.Count -ne 6 -or $pb.Count -ne 6) { return $false }
    return ($pa[1] -eq $pb[1] -and $pa[2] -eq $pb[2] -and $pa[3] -eq $pb[3] -and $pa[4] -eq $pb[4])
}

function Get-PingStats([string]$Target, $Rtts, [int]$Lost, [int]$Sent) {
    if ($Rtts.Count -eq 0) {
        return [pscustomobject]@{ Target = $Target; Sent = $Sent; LossPct = 100; AvgMs = $null; MinMs = $null; P95Ms = $null; MaxMs = $null; JitterMs = $null }
    }
    $sorted = @($Rtts | Sort-Object)
    $avg = ($Rtts | Measure-Object -Average).Average
    $p95 = $sorted[[math]::Min($sorted.Count - 1, [int][math]::Floor($sorted.Count * 0.95))]
    $j = 0.0
    for ($i = 1; $i -lt $Rtts.Count; $i++) { $j += [math]::Abs($Rtts[$i] - $Rtts[$i - 1]) }
    $jit = if ($Rtts.Count -gt 1) { $j / ($Rtts.Count - 1) } else { 0 }
    [pscustomobject]@{
        Target   = $Target; Sent = $Sent
        LossPct  = [math]::Round(100.0 * $Lost / $Sent, 1)
        AvgMs    = [math]::Round($avg, 1); MinMs = $sorted[0]; P95Ms = $p95; MaxMs = $sorted[-1]
        JitterMs = [math]::Round($jit, 1)
    }
}

function Measure-Ping([string]$Target, [int]$Count = 50, [int]$IntervalMs = 100, [int]$TimeoutMs = 1000, [scriptblock]$While) {
    $p = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[double]
    $lost = 0; $sent = 0
    for ($i = 0; $i -lt $Count; $i++) {
        if ($While -and -not (& $While)) { break }
        $sent++
        try {
            $r = $p.Send($Target, $TimeoutMs)
            if ($r.Status -eq 'Success') { $rtts.Add([double]$r.RoundtripTime) } else { $lost++ }
        } catch { $lost++ }
        Start-Sleep -Milliseconds $IntervalMs
    }
    $p.Dispose()
    if ($sent -eq 0) { return $null }
    Get-PingStats $Target $rtts $lost $sent
}

function Format-Ping($s) {
    if (-not $s) { return 'n/a' }
    if ($null -eq $s.AvgMs) { return "100% loss ($($s.Sent) pings)" }
    "avg $($s.AvgMs) ms, p95 $($s.P95Ms) ms, max $($s.MaxMs) ms, jitter $($s.JitterMs) ms, loss $($s.LossPct)% ($($s.Sent) pings)"
}

# ---------------------------------------------------------------- 1. Wi-Fi link

Write-Step 'Reading Wi-Fi connection (netsh wlan show interfaces)'
$ifLines = @(netsh wlan show interfaces 2>&1 | ForEach-Object { "$_" })
Save-Raw 'netsh-interfaces' $ifLines

# split into one block per adapter, use the connected one
$blocks = @(); $cur = $null
foreach ($l in $ifLines) {
    if ($l -match '^\s*Name\s*:') { if ($cur) { $blocks += , $cur }; $cur = @() }
    if ($null -ne $cur) { $cur += $l }
}
if ($cur) { $blocks += , $cur }

$wifi = $null
foreach ($b in $blocks) {
    $kv = @(Get-KeyValues $b)
    if (Get-Field $kv '^SSID$') { $wifi = $kv; break }
}

$Link = $null
if (-not $wifi) {
    if (($ifLines -join ' ') -match 'location|Standort') {
        Add-Finding High 'Windows' 'Windows blocks Wi-Fi details because Location access is off.' `
            'Settings > Privacy & security > Location: turn on "Location services" and "Let desktop apps access your location", then run this again.'
    } else {
        Add-Finding High 'Wi-Fi' 'This PC is not connected to a Wi-Fi network (or has no Wi-Fi adapter).' `
            'Connect this PC to the Wi-Fi you want to analyse and run the script again.'
    }
} else {
    $ch = ConvertTo-Num (Get-Field $wifi '^(Channel|Kanal)$')
    $Link = [pscustomobject]@{
        Adapter     = Get-Field $wifi '^Name$'
        Description = Get-Field $wifi '^(Description|Beschreibung)$'
        SSID        = Get-Field $wifi '^SSID$'
        BSSID       = Get-Field $wifi '^(AP )?BSSID$'
        RadioType   = Get-Field $wifi '^(Radio type|Funktyp)$'
        BandText    = Get-Field $wifi '^Band$'
        Channel     = $ch
        Band        = $null
        RxMbps      = ConvertTo-Num (Get-Field $wifi '^(Receive rate|Empfangsrate)')
        TxMbps      = ConvertTo-Num (Get-Field $wifi 'bertragungsrate|^Transmit rate')
        SignalPct   = ConvertTo-Num (Get-Field $wifi '^Signal$')
        SignalDbm   = $null
        Auth        = Get-Field $wifi '^(Authentication|Authentifizierung)$'
        Cipher      = Get-Field $wifi '^(Cipher|Verschl)'
    }
    $Link.Band = Get-BandName $Link.BandText $Link.Channel
    if ($null -ne $Link.SignalPct) { $Link.SignalDbm = [int]($Link.SignalPct / 2 - 100) }
    $Data.Link = $Link
    Write-Host ("   {0} on {1} GHz, channel {2}, {3}, signal {4}% (~{5} dBm), rate rx {6} / tx {7} Mbit/s" -f `
        $Link.SSID, $Link.Band, $Link.Channel, $Link.RadioType, $Link.SignalPct, $Link.SignalDbm, $Link.RxMbps, $Link.TxMbps)
}

# ---------------------------------------------------------------- 2. Adapter / driver capabilities

Write-Step 'Reading Wi-Fi adapter and driver'
$drvLines = @(netsh wlan show drivers 2>&1 | ForEach-Object { "$_" })
Save-Raw 'netsh-drivers' $drvLines
$drvKv = @(Get-KeyValues $drvLines)
$supported = Get-Field $drvKv '^(Radio types supported|Unterst.*Funktypen)'
$Data.AdapterRadioTypes = $supported
$adapterAx = $supported -match '802\.11(ax|be)'
$adapterAc = $supported -match '802\.11(ac|ax|be)'
$adapter5  = $supported -match '802\.11(a|ac|ax|be)\b'

$na = $null
if ($Link) { $na = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Link.Adapter -or $_.InterfaceDescription -eq $Link.Description } | Select-Object -First 1 }
if (-not $na) { $na = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.PhysicalMediaType -match '802\.11|Native 802.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN') } | Select-Object -First 1 }

if ($na) {
    $drv = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName -eq $na.InterfaceDescription } | Select-Object -First 1
    $Data.Adapter = [pscustomobject]@{
        Name = $na.Name; Description = $na.InterfaceDescription; LinkSpeed = $na.LinkSpeed
        DriverVersion = $drv.DriverVersion; DriverDate = if ($drv.DriverDate) { $drv.DriverDate.ToString('yyyy-MM-dd') } else { $null }
        DriverProvider = $drv.DriverProviderName
    }
    Write-Host "   $($na.InterfaceDescription), driver $($drv.DriverVersion) from $($Data.Adapter.DriverDate)"

    if ($drv.DriverDate -and $drv.DriverDate -lt (Get-Date).AddYears(-2)) {
        Add-Finding Medium 'Adapter' "The Wi-Fi driver is old ($($Data.Adapter.DriverDate), version $($drv.DriverVersion)). Old drivers often have throughput and roaming bugs." `
            "Install the latest driver from the chip maker (e.g. Intel Driver & Support Assistant, Realtek, MediaTek, Qualcomm) or the laptop manufacturer, not only via Windows Update."
    }

    $adv = @(Get-NetAdapterAdvancedProperty -Name $na.Name -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayValue)
    Save-Raw 'adapter-advanced-properties' ($adv | Format-Table -AutoSize | Out-String -Width 300)
    $Data.AdapterAdvanced = $adv
    foreach ($p in $adv) {
        if ($p.DisplayName -match 'Preferred Band|Bevorzugtes Band|Band Preference' -and $p.DisplayValue -match '2[.,]4') {
            Add-Finding Medium 'Adapter' "The adapter setting '$($p.DisplayName)' is '$($p.DisplayValue)', so it prefers the slower 2.4 GHz band." `
                "Device Manager > Network adapters > $($na.InterfaceDescription) > Advanced > '$($p.DisplayName)': choose 5 GHz (or 6 GHz) preferred."
        }
        if ($p.DisplayName -match 'Channel Width.*5|Kanalbreite.*5|Bandwidth.*5' -and $p.DisplayValue -match '^\s*20\s*MHz') {
            Add-Finding Medium 'Adapter' "The adapter limits 5 GHz channel width ('$($p.DisplayName)' = '$($p.DisplayValue)'). That caps speed to about a quarter." `
                "Set '$($p.DisplayName)' to Auto in the adapter's Advanced properties."
        }
        if ($p.DisplayName -match 'Wireless Mode|Drahtlosmodus|802\.11 Mode' -and $p.DisplayValue -match '^(802\.11)?\s*[abg/]+$') {
            Add-Finding High 'Adapter' "The adapter is restricted to an old Wi-Fi mode ('$($p.DisplayName)' = '$($p.DisplayValue)')." `
                "Set '$($p.DisplayName)' to the highest option (e.g. 802.11ax or 'Auto')."
        }
    }

    $pm = Get-NetAdapterPowerManagement -Name $na.Name -ErrorAction SilentlyContinue
    if ($pm -and "$($pm.AllowComputerToTurnOffDevice)" -eq 'Enabled') {
        Add-Finding Low 'Power' 'Windows may turn off the Wi-Fi adapter to save power, which can cause short drop-outs.' `
            "Device Manager > $($na.InterfaceDescription) > Power Management: untick 'Allow the computer to turn off this device to save power'."
    }
} else {
    Add-Finding Info 'Adapter' 'Could not identify the Wi-Fi adapter in Get-NetAdapter.'
}

# Power plan: Wireless Adapter Settings > Power Saving Mode (0 = Maximum Performance ... 3 = Maximum Power Saving)
$pc = @(powercfg /query SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 2>&1 | ForEach-Object { "$_" })
Save-Raw 'powercfg-wireless' $pc
$hex = @([regex]::Matches(($pc -join "`n"), '0x[0-9a-fA-F]{8}') | ForEach-Object { [Convert]::ToInt32($_.Value, 16) })
if ($hex.Count -ge 2) {
    $ac = $hex[-2]; $dc = $hex[-1]
    $Data.WirelessPowerSaving = @{ PluggedIn = $ac; Battery = $dc }
    if ($ac -gt 0) {
        Add-Finding Medium 'Power' "Wi-Fi power saving is active even when plugged in (level $ac of 3). This adds latency spikes and lowers throughput." `
            "Control Panel > Power Options > Change plan settings > Change advanced power settings > Wireless Adapter Settings > Power Saving Mode: 'Maximum Performance' for 'Plugged in'."
    }
    if ($dc -ge 2) {
        Add-Finding Low 'Power' "Wi-Fi power saving on battery is set high (level $dc of 3)." `
            "Same setting as above, 'On battery': 'Low Power Saving' or 'Maximum Performance' if you need speed on battery."
    }
}

# ---------------------------------------------------------------- 3. Link quality findings

if ($Link) {
    $s = $Link.SignalPct
    if ($null -ne $s) {
        if ($s -lt 40) {
            Add-Finding High 'Signal' "Weak signal: $s% (~$($Link.SignalDbm) dBm). Below about -75 dBm the link rate collapses and retransmissions slow everyone down." `
                'Move the router to a central, raised, open spot (not in a cabinet, behind a TV or near metal/water), or add a mesh node / access point closer to this room. Wired backhaul is best.'
        } elseif ($s -lt 60) {
            Add-Finding Medium 'Signal' "Moderate signal: $s% (~$($Link.SignalDbm) dBm). Enough for browsing, but limits top speed." `
                'Reduce walls/floors between PC and router, reposition the router, or add a mesh node.'
        } else {
            Add-Finding OK 'Signal' "Signal is good: $s% (~$($Link.SignalDbm) dBm)."
        }
    }

    if ($Link.RadioType -match '802\.11[abg]$') {
        Add-Finding High 'Standard' "Connected with old $($Link.RadioType) (max 54 Mbit/s)." `
            'Make sure the router has 802.11n/ac/ax enabled (not a "legacy"/"b/g only" mode) and uses WPA2-AES or WPA3, not WEP/TKIP.'
    } elseif ($Link.RadioType -match '802\.11n$' -and $adapterAc) {
        Add-Finding Medium 'Standard' "Connected with 802.11n (Wi-Fi 4) although this adapter supports $supported." `
            'Connect on 5 GHz; check the router has Wi-Fi 5/6 (802.11ac/ax) enabled. If the router only does 802.11n, it is due for replacement.'
    } elseif ($Link.RadioType -match '802\.11ac$' -and $adapterAx) {
        Add-Finding Info 'Standard' 'Connected with Wi-Fi 5 (802.11ac); this PC supports Wi-Fi 6/6E. Either the router is Wi-Fi 5 or Wi-Fi 6 (802.11ax) is disabled on it.' `
            'Check the router settings for an 802.11ax / Wi-Fi 6 option. Not urgent unless many devices share the network.'
    }

    if ($Link.Cipher -match 'TKIP|WEP' -or $Link.Auth -match 'WEP') {
        Add-Finding High 'Security' "The network uses $($Link.Auth) / $($Link.Cipher). WEP and TKIP force Wi-Fi down to 54 Mbit/s and are insecure." `
            'In the router set security to WPA2-Personal (AES/CCMP only) or WPA2/WPA3 mixed.'
    } elseif ($Link.Auth -match '^Open|Offen') {
        Add-Finding High 'Security' 'The Wi-Fi is open (no password). Anyone nearby can use your bandwidth.' `
            'Enable WPA2/WPA3-Personal with a strong password.'
    }

    if ($Link.RxMbps) {
        $low = if ($Link.Band -eq '2.4') { 72 } else { 200 }
        if ($Link.RxMbps -lt $low) {
            Add-Finding Medium 'Link rate' "Link rate is low: $($Link.RxMbps) Mbit/s receive / $($Link.TxMbps) Mbit/s transmit on $($Link.Band) GHz. Real throughput is roughly half of this." `
                'Usually caused by weak signal, interference, a narrow channel width (20 MHz) or an old Wi-Fi mode. See the other findings.'
        }
    }
}

# ---------------------------------------------------------------- 4. Neighbouring networks

Write-Step 'Scanning neighbouring networks (netsh wlan show networks mode=bssid)'
$netLines = @(netsh wlan show networks mode=bssid 2>&1 | ForEach-Object { "$_" })
Save-Raw 'netsh-networks' $netLines

$nets = New-Object System.Collections.Generic.List[object]
$curSsid = $null; $bss = $null
foreach ($l in $netLines) {
    if ($l -match '^SSID \d+\s*:\s?(.*)$') { $curSsid = $Matches[1].Trim(); $bss = $null; continue }
    if ($l -match '^\s+BSSID \d+\s*:\s?(.*)$') {
        $bss = [pscustomobject]@{ SSID = $curSsid; BSSID = $Matches[1].Trim(); Signal = $null; Radio = $null; BandText = $null; Band = $null; Channel = $null; Stations = $null; UtilPct = $null }
        $nets.Add($bss); continue
    }
    if ($bss -and $l -match '^\s*([^:]+?)\s*:\s(.*)$') {
        $k = $Matches[1].Trim(); $v = $Matches[2].Trim()
        if     ($k -match '^Signal$')                            { $bss.Signal = ConvertTo-Num $v }
        elseif ($k -match '^(Radio type|Funktyp)$')              { $bss.Radio = $v }
        elseif ($k -match '^Band$')                              { $bss.BandText = $v }
        elseif ($k -match '^(Channel|Kanal)$')                   { $bss.Channel = ConvertTo-Num $v }
        elseif ($k -match '^(Connected Stations|Verbundene)')    { $bss.Stations = ConvertTo-Num $v }
        elseif ($k -match '^(Channel Utili|Kanalauslastung)') {
            $m = [regex]::Match($v, '\((\d+)\s*%\)')
            if ($m.Success) { $bss.UtilPct = [int]$m.Groups[1].Value }
            else { $n = ConvertTo-Num $v; if ($null -ne $n) { $bss.UtilPct = [int][math]::Round($n / 255 * 100) } }
        }
    }
}
foreach ($n in $nets) { $n.Band = Get-BandName $n.BandText $n.Channel }
$Data.Networks = $nets
Write-Host "   $($nets.Count) access points visible"

if ($nets.Count -eq 0 -and ($netLines -join ' ') -match 'location|Standort') {
    Add-Finding Medium 'Windows' 'Windows blocked the network scan because Location access is off, so channel congestion could not be checked.' `
        'Settings > Privacy & security > Location: turn on "Location services" and "Let desktop apps access your location", then run this again.'
}

if ($Link -and $nets.Count -gt 0) {
    $myB = $Link.BSSID
    $mine     = $nets | Where-Object { $_.BSSID -eq $myB } | Select-Object -First 1
    $ownRouter = @($nets | Where-Object { $_.BSSID -ne $myB -and (Test-SameDevice $_.BSSID $myB) })
    $ownMesh  = @($nets | Where-Object { $_.SSID -eq $Link.SSID -and $_.BSSID -ne $myB -and -not (Test-SameDevice $_.BSSID $myB) })
    $foreign  = @($nets | Where-Object { $_.BSSID -ne $myB -and -not (Test-SameDevice $_.BSSID $myB) -and $_.SSID -ne $Link.SSID })

    # 2.4 GHz while 5/6 GHz of the same network is reachable
    if ($Link.Band -eq '2.4') {
        $alt = @($nets | Where-Object { $_.SSID -eq $Link.SSID -and $_.Band -ne '2.4' } | Sort-Object Signal -Descending)
        if ($alt.Count -gt 0) {
            Add-Finding High 'Band' "Connected on slow, crowded 2.4 GHz although '$($Link.SSID)' is also available on $($alt[0].Band) GHz here (signal $($alt[0].Signal)%)." `
                'Enable band steering on the router, or give the 5 GHz network its own name and connect to that. Also check the adapter "Preferred Band" setting.'
        } elseif ($adapter5) {
            Add-Finding Medium 'Band' 'Connected on 2.4 GHz and no 5 GHz network from your router is visible. 2.4 GHz is slow and shared with neighbours, Bluetooth and microwaves.' `
                'Enable the 5 GHz radio on the router if it has one. If it does not, a dual-band (Wi-Fi 6) router is the biggest single improvement.'
        }
        if (Get-PnpDevice -Class Bluetooth -Status OK -ErrorAction SilentlyContinue | Select-Object -First 1) {
            Add-Finding Info 'Interference' 'Bluetooth is active. On many laptops Wi-Fi and Bluetooth share one antenna, which hurts 2.4 GHz Wi-Fi in particular.' `
                'Use 5 GHz Wi-Fi, or turn off Bluetooth when you need full speed.'
        }
    }

    if ($Link.Band -eq '2.4' -and $Link.Channel) {
        $overlap = @($foreign | Where-Object { $_.Band -eq '2.4' -and $_.Channel -and [math]::Abs($_.Channel - $Link.Channel) -lt 5 })
        $strong  = @($overlap | Where-Object { $_.Signal -ge 50 })
        if ($Link.Channel -notin 1, 6, 11) {
            Add-Finding Medium 'Channel' "Your router uses 2.4 GHz channel $($Link.Channel). Only 1, 6 and 11 do not overlap; in-between channels get interference from two sides." `
                'Set the 2.4 GHz channel to 1, 6 or 11 (see the recommendation below) and the 2.4 GHz channel width to 20 MHz.'
        }
        $best = foreach ($c in 1, 6, 11) {
            $score = 0
            foreach ($n in $nets) {
                if ($n.Band -eq '2.4' -and $n.Channel -and $n.BSSID -ne $myB -and -not (Test-SameDevice $n.BSSID $myB) -and [math]::Abs($n.Channel - $c) -lt 5) { $score += [math]::Max($n.Signal, 1) }
            }
            [pscustomobject]@{ Channel = $c; Score = $score }
        }
        $Data.Best24 = $best
        $bestCh = ($best | Sort-Object Score | Select-Object -First 1)
        $myScore = ($overlap | Measure-Object -Property Signal -Sum).Sum
        if ($overlap.Count -ge 3 -or $strong.Count -ge 1) {
            $sev = if ($strong.Count -ge 2) { 'High' } else { 'Medium' }
            $fix = if ($bestCh.Channel -ne $Link.Channel -and $bestCh.Score -lt $myScore) { "Change the router's 2.4 GHz channel to $($bestCh.Channel) (least used here). Better: use 5 GHz." } else { 'Your channel is already the least bad of 1/6/11. Use 5 GHz for anything that needs speed.' }
            Add-Finding $sev 'Congestion' "$($overlap.Count) neighbouring networks overlap your 2.4 GHz channel $($Link.Channel) ($($strong.Count) of them strong). They share airtime with you." $fix
        }
    }

    if ($Link.Band -in '5', '6' -and $Link.Channel) {
        $myBlock = Get-Block80 $Link.Channel
        $same    = @($foreign | Where-Object { $_.Band -eq $Link.Band -and $_.Channel -eq $Link.Channel })
        $block   = @($foreign | Where-Object { $_.Band -eq '5' -and $Link.Band -eq '5' -and (Get-Block80 $_.Channel) -eq $myBlock })
        if ($same.Count -ge 2 -or @($same | Where-Object { $_.Signal -ge 60 }).Count -ge 1) {
            $counts = $foreign | Where-Object { $_.Band -eq '5' } | Group-Object { Get-Block80 $_.Channel }
            $cands = '36-48', '52-64 (DFS)', '100-112 (DFS)', '116-128 (DFS)', '132-144 (DFS)', '149-161' | ForEach-Object {
                $k = $_; $c = ($counts | Where-Object { $_.Name -eq $k }).Count; [pscustomobject]@{ Block = $k; Count = [int]$c }
            }
            $free = ($cands | Sort-Object Count | Select-Object -First 1)
            Add-Finding Medium 'Congestion' "$($same.Count) neighbouring networks use the same 5 GHz channel $($Link.Channel) ($($block.Count) in the same 80 MHz block $myBlock)." `
                "Move the router's 5 GHz radio to channels $($free.Block) ($($free.Count) networks there). DFS channels are often empty but can briefly drop when radar is detected."
        }
    }

    if ($mine -and $null -ne $mine.UtilPct) {
        $Data.OwnChannelUtilisation = $mine.UtilPct
        if ($mine.UtilPct -ge 70) {
            Add-Finding High 'Congestion' "Your router reports its channel is busy $($mine.UtilPct)% of the time ($($mine.Stations) devices connected to it)." `
                'Change channel (see above), move devices that can to 5 GHz/cable, and find any device that is streaming or uploading constantly.'
        } elseif ($mine.UtilPct -ge 45) {
            Add-Finding Medium 'Congestion' "Your router reports its channel is busy $($mine.UtilPct)% of the time ($($mine.Stations) devices connected)." `
                'Consider a less crowded channel and moving stationary devices (TV, console, PC) to cable.'
        }
    }

    if ($ownMesh.Count -gt 0) {
        $better = @($ownMesh | Where-Object { $_.Signal -gt ($Link.SignalPct + 20) } | Sort-Object Signal -Descending)
        if ($better.Count -gt 0) {
            Add-Finding Medium 'Roaming' "This PC stays on a weaker access point ($($Link.SignalPct)%) although another one for '$($Link.SSID)' is much stronger here ($($better[0].Signal)%, $($better[0].BSSID))." `
                "Set the adapter's 'Roaming Aggressiveness' to Medium-High, enable 802.11k/v (fast roaming) on the router/mesh, or toggle Wi-Fi off/on."
        }
    }
    $Data.OwnRouterOtherRadios = $ownRouter
}

# ---------------------------------------------------------------- 5. Router / gateway

Write-Step 'Finding the router'
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
$gw = if ($route) { $route.NextHop } else { $null }
$ifIndex = if ($na) { $na.ifIndex } elseif ($route) { $route.InterfaceIndex } else { $null }
if ($route -and $na -and $route.InterfaceIndex -ne $na.ifIndex) {
    $other = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    Add-Finding Info 'Routing' "Internet traffic currently goes through '$($other.Name)' ($($other.InterfaceDescription)), not the Wi-Fi adapter. Speed results below are for that connection." ''
}
$Data.Gateway = $gw
if ($gw) {
    Write-Host "   Router: $gw"
    $gwMac = (Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
    $title = $null; $server = $null
    try {
        $r = Invoke-WebRequest -Uri "http://$gw/" -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 3 -ErrorAction Stop
        $server = $r.Headers['Server']
        $m = [regex]::Match($r.Content, '<title[^>]*>\s*([^<]{1,120})', 'IgnoreCase')
        if ($m.Success) { $title = $m.Groups[1].Value.Trim() }
    } catch {
        try {
            $resp = $_.Exception.Response
            if ($resp) { $server = $resp.Headers['Server'] }
        } catch {}
    }
    $Data.Router = [pscustomobject]@{ IP = $gw; MAC = $gwMac; AdminPageTitle = $title; ServerHeader = $server }
    if ($title -or $server) { Write-Host "   Admin page: '$title' $server" }
}

# ---------------------------------------------------------------- 6. Latency: router vs internet

$gwStats = $null; $inetStats = $null
if ($gw) {
    Write-Step "Measuring latency to the router ($GatewayPings pings, ~$([int]($GatewayPings * 0.15)) s)"
    $gwStats = Measure-Ping $gw $GatewayPings 100 1000
    Write-Host "   $(Format-Ping $gwStats)"
    $Data.PingRouter = $gwStats
    if ($gwStats.LossPct -ge 100) {
        Add-Finding Info 'Router' 'The router does not answer ping, so Wi-Fi latency could not be measured directly.' ''
        $gwStats = $null
    } elseif ($gwStats.LossPct -ge 2 -or $gwStats.AvgMs -ge 15 -or $gwStats.P95Ms -ge 50) {
        Add-Finding High 'Wi-Fi latency' "The Wi-Fi link to the router itself is unstable: $(Format-Ping $gwStats). A healthy Wi-Fi link is ~1-5 ms with no loss." `
            'This points at the Wi-Fi (signal, interference, congestion, power saving), not your internet provider. Fix the signal/channel findings first.'
    } elseif ($gwStats.AvgMs -ge 6 -or $gwStats.JitterMs -ge 8 -or $gwStats.P95Ms -ge 25) {
        Add-Finding Medium 'Wi-Fi latency' "Latency to the router is higher or spikier than ideal: $(Format-Ping $gwStats)." `
            'Typical causes: Wi-Fi power saving, background scans, a busy channel. See the other findings.'
    } else {
        Add-Finding OK 'Wi-Fi latency' "Wi-Fi link to the router is stable: $(Format-Ping $gwStats)."
    }
}

Write-Step 'Measuring latency to the internet (1.1.1.1, 8.8.8.8)'
$inet1 = Measure-Ping '1.1.1.1' 50 100 2000
$inet2 = Measure-Ping '8.8.8.8' 50 100 2000
$Data.PingInternet = @($inet1, $inet2)
Write-Host "   1.1.1.1: $(Format-Ping $inet1)"
Write-Host "   8.8.8.8: $(Format-Ping $inet2)"
$inetStats = @($inet1, $inet2) | Where-Object { $null -ne $_.AvgMs } | Sort-Object AvgMs | Select-Object -First 1
if (-not $inetStats) {
    Add-Finding High 'Internet' 'No answer from 1.1.1.1 or 8.8.8.8. The internet connection is down or ping is blocked (VPN/firewall).' ''
} else {
    $wifiOk = $gwStats -and $gwStats.LossPct -lt 2 -and $gwStats.AvgMs -lt 15
    if ($inetStats.LossPct -ge 2 -and $wifiOk) {
        Add-Finding High 'Internet line' "Packet loss to the internet ($($inetStats.LossPct)%) while the Wi-Fi to the router is clean. The problem is the router's internet line or the provider." `
            'Restart modem/router; check the DSL/cable line status page in the router; contact your provider with these numbers.'
    }
    $extra = if ($gwStats) { $inetStats.AvgMs - $gwStats.AvgMs } else { $inetStats.AvgMs }
    if ($extra -ge 60) {
        Add-Finding Medium 'Internet line' "High base latency beyond the router: ~$([int]$extra) ms (typical fibre/cable 5-25 ms, DSL 10-40 ms)." `
            'Check for a VPN, interleaving on DSL (ask provider for fast path), or an overloaded line.'
    }
}

# ---------------------------------------------------------------- 7. Speed + bufferbloat

if (-not $NoSpeedTest) {
    Write-Step 'Download speed test (speed.cloudflare.com, 4 streams, ~12 s) with latency under load'
    $dl = {
        param($Url, $Seconds)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $total = 0L; $sw = $null; $req = $null
        try {
            $req = [Net.HttpWebRequest]::Create($Url); $req.Timeout = 15000; $req.ReadWriteTimeout = 15000
            $resp = $req.GetResponse(); $st = $resp.GetResponseStream(); $buf = New-Object byte[] 262144
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($sw.Elapsed.TotalSeconds -lt $Seconds) { $n = $st.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $total += $n }
            $secs = $sw.Elapsed.TotalSeconds; $req.Abort()
            [pscustomobject]@{ Bytes = $total; Seconds = $secs; Error = $null }
        } catch {
            $secs = if ($sw) { $sw.Elapsed.TotalSeconds } else { 0 }
            [pscustomobject]@{ Bytes = $total; Seconds = $secs; Error = $_.Exception.Message }
        }
    }
    $jobs = 1..4 | ForEach-Object { Start-Job -ScriptBlock $dl -ArgumentList "https://speed.cloudflare.com/__down?bytes=500000000&r=$_", 12 }
    Start-Sleep -Seconds 3   # let jobs start and ramp up
    $loaded = Measure-Ping '1.1.1.1' 150 100 2000 { @($jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0 }
    $res = $jobs | Wait-Job -Timeout 40 | Receive-Job
    $jobs | Remove-Job -Force
    $ok = @($res | Where-Object { $_.Seconds -gt 1 })
    $mbps = 0
    foreach ($r in $ok) { $mbps += $r.Bytes * 8 / $r.Seconds / 1e6 }
    $mbps = [math]::Round($mbps, 1)
    $Data.Speed = [pscustomobject]@{ DownloadMbps = $mbps; Streams = $res; LoadedPing = $loaded }
    Write-Host "   Download: $mbps Mbit/s"
    Write-Host "   Latency under load: $(Format-Ping $loaded)"

    if ($mbps -le 0) {
        $err = ($res | Where-Object Error | Select-Object -First 1).Error
        Add-Finding Info 'Speed' "Speed test failed: $err" ''
    } else {
        if ($Link -and $Link.RxMbps -and $route -and $na -and $route.InterfaceIndex -eq $na.ifIndex) {
            $wifiCap = [math]::Round($Link.RxMbps * 0.6)
            if ($mbps -ge 0.8 * $wifiCap) {
                Add-Finding High 'Bottleneck' "Download $mbps Mbit/s is at the limit of the Wi-Fi link (link rate $($Link.RxMbps) Mbit/s gives ~$wifiCap Mbit/s real). The Wi-Fi is the bottleneck, not your internet plan." `
                    'Improve the link: 5/6 GHz, better signal, wider channel (80 MHz on 5 GHz), newer router/adapter. Test with a LAN cable to see what the line delivers.'
            } else {
                Add-Finding Info 'Bottleneck' "Download $mbps Mbit/s while the Wi-Fi link could carry ~$wifiCap Mbit/s. If this is well below your internet plan, compare with a LAN cable: if wired is also slow, it's the line/provider or router, not Wi-Fi." ''
            }
        }
        if ($loaded -and $null -ne $loaded.AvgMs -and $inetStats) {
            $bloat = $loaded.AvgMs - $inetStats.AvgMs
            $Data.BufferbloatMs = [math]::Round($bloat, 1)
            if ($bloat -ge 100) {
                Add-Finding High 'Bufferbloat' "Latency rises by ~$([int]$bloat) ms when the line is busy. Calls, games and browsing lag whenever someone downloads/uploads." `
                    'Enable SQM / Smart Queue / "Adaptive QoS" (FRITZ!Box: Internet > Filters > Prioritisation; check your router), and set it slightly below your real speed.'
            } elseif ($bloat -ge 30) {
                Add-Finding Medium 'Bufferbloat' "Latency rises by ~$([int]$bloat) ms under load (bufferbloat)." `
                    'Enable QoS/SQM in the router if available.'
            }
        }
    }
}

# ---------------------------------------------------------------- 8. DNS

Write-Step 'Measuring DNS response time'
$dnsServers = @()
if ($ifIndex) { $dnsServers = @((Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses) }
$names = 'wikipedia.org', 'microsoft.com', 'github.com', 'bbc.co.uk', 'amazon.com'
$dnsRes = foreach ($srv in ($dnsServers + '1.1.1.1' | Select-Object -Unique)) {
    $times = @(); $fail = 0
    foreach ($n in $names) {
        try {
            $t = (Measure-Command { Resolve-DnsName -Name $n -Server $srv -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null }).TotalMilliseconds
            $times += $t
        } catch { $fail++ }
    }
    $avg = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average) } else { $null }
    [pscustomobject]@{ Server = $srv; Configured = ($srv -in $dnsServers); AvgMs = $avg; Failures = $fail }
}
$Data.Dns = $dnsRes
$dnsRes | ForEach-Object { Write-Host "   $($_.Server): avg $($_.AvgMs) ms, $($_.Failures) failures" }
$cfg = @($dnsRes | Where-Object Configured)
$ref = $dnsRes | Where-Object { $_.Server -eq '1.1.1.1' }
foreach ($d in $cfg) {
    if ($d.Failures -ge 2 -or ($d.AvgMs -and $d.AvgMs -ge 150 -and $ref.AvgMs -and $d.AvgMs -gt 3 * $ref.AvgMs)) {
        Add-Finding Medium 'DNS' "Your DNS server $($d.Server) is slow or unreliable (avg $($d.AvgMs) ms, $($d.Failures) failures; 1.1.1.1: $($ref.AvgMs) ms). Every new website waits for this." `
            'In the router, set the upstream DNS to a fast resolver (e.g. 1.1.1.1 / 9.9.9.9) or your provider''s recommended one.'
    }
}

# ---------------------------------------------------------------- 9. Devices on the network

Write-Step 'Finding devices on the network'
$ipObj = if ($ifIndex) { Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1 } else { $null }
if ($ipObj -and -not $NoSweep -and $ipObj.PrefixLength -ge 24) {
    $base3 = ($ipObj.IPAddress -split '\.')[0..2] -join '.'
    Write-Host "   Pinging $base3.1-254 to wake up devices..."
    $tasks = foreach ($i in 1..254) { (New-Object System.Net.NetworkInformation.Ping).SendPingAsync("$base3.$i", 700) }
    try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, 5000) | Out-Null } catch {}
}
$devices = @()
if ($ifIndex) {
    $devices = @(Get-NetNeighbor -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe' -and
            $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and
            $_.IPAddress -notmatch '^(22[4-9]|23\d)\.|\.255$'
        } | ForEach-Object {
            $nb = $_; $name = $null
            try { $name = (Resolve-DnsName -Name $nb.IPAddress -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch {}
            [pscustomobject]@{ IP = $nb.IPAddress; MAC = $nb.LinkLayerAddress; Name = $name; Random = ($nb.LinkLayerAddress -match '^.[26AaEe]') }
        })
}
$Data.Devices = $devices
Write-Host "   $($devices.Count) other devices found"
if ($devices.Count -ge 25) {
    Add-Finding Info 'Devices' "$($devices.Count) devices are active on the network. Every Wi-Fi device takes airtime; slow or distant ones take the most." `
        'Put stationary devices (TV, console, desktop) on cable; check the list in the report for devices you do not recognise.'
}

# ---------------------------------------------------------------- 10. This PC: VPNs, busy programs

Write-Step 'Checking this PC for VPNs and busy programs'
$vpn = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'VPN|TAP-|WireGuard|Wintun|OpenVPN|Fortinet|AnyConnect|NordLynx|Proton|Tunnel|ZeroTier|Tailscale' })
if ($vpn.Count) {
    Add-Finding Low 'VPN' "VPN/tunnel adapter active: $(($vpn | ForEach-Object { $_.InterfaceDescription }) -join ', '). If all traffic goes through it, speed and latency depend on the VPN server." `
        'Disconnect the VPN and compare.'
}
$procs = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
    Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
        $p = Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue
        [pscustomobject]@{ Process = if ($p) { $p.ProcessName } else { "PID $($_.Name)" }; Connections = $_.Count }
    }
$Data.TopConnections = $procs
$heavy = @($procs | Where-Object { $_.Process -match 'OneDrive|Dropbox|GoogleDrive|steam|EpicGames|Battle\.net|qbittorrent|uTorrent|BitTorrent|Origin|EADesktop' })
if ($heavy.Count) {
    Add-Finding Low 'This PC' "Programs that often sync or download in the background are running: $(($heavy | ForEach-Object Process) -join ', ')." `
        'Pause syncing/downloads while you need full speed, or limit their bandwidth in their settings.'
}

# ---------------------------------------------------------------- report

$order = @{ High = 0; Medium = 1; Low = 2; Info = 3; OK = 4 }
$sorted = $Findings | Sort-Object { $order[$_.Severity] }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Wi-Fi analysis  $($Data.Timestamp)  on $($Data.Computer)")
[void]$sb.AppendLine(('=' * 70))
if ($Link) {
    [void]$sb.AppendLine("Network : $($Link.SSID)  ($($Link.BSSID))")
    [void]$sb.AppendLine("Link    : $($Link.Band) GHz, channel $($Link.Channel), $($Link.RadioType), $($Link.Auth)/$($Link.Cipher)")
    [void]$sb.AppendLine("Signal  : $($Link.SignalPct)% (~$($Link.SignalDbm) dBm)   rate rx $($Link.RxMbps) / tx $($Link.TxMbps) Mbit/s")
}
if ($Data.Adapter) { [void]$sb.AppendLine("Adapter : $($Data.Adapter.Description), driver $($Data.Adapter.DriverVersion) ($($Data.Adapter.DriverDate)); supports $supported") }
if ($Data.Router)  { [void]$sb.AppendLine("Router  : $($Data.Router.IP)  MAC $($Data.Router.MAC)  '$($Data.Router.AdminPageTitle)' $($Data.Router.ServerHeader)") }
[void]$sb.AppendLine("Ping router   : $(Format-Ping $Data.PingRouter)")
[void]$sb.AppendLine("Ping internet : $(Format-Ping $inetStats)")
if ($Data.Speed) {
    [void]$sb.AppendLine("Download      : $($Data.Speed.DownloadMbps) Mbit/s")
    [void]$sb.AppendLine("Ping in load  : $(Format-Ping $Data.Speed.LoadedPing)")
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('FINDINGS (most important first)')
[void]$sb.AppendLine(('-' * 70))
$i = 0
foreach ($f in $sorted) {
    $i++
    [void]$sb.AppendLine("$i. [$($f.Severity)] $($f.Area): $($f.Finding)")
    if ($f.Fix) { [void]$sb.AppendLine("   Fix: $($f.Fix)") }
}
[void]$sb.AppendLine('')
if ($nets.Count) {
    [void]$sb.AppendLine('VISIBLE NETWORKS')
    [void]$sb.AppendLine(($nets | Sort-Object Band, Channel | Format-Table SSID, BSSID, Band, Channel, Signal, Radio, Stations, UtilPct -AutoSize | Out-String -Width 200))
}
if ($devices.Count) {
    [void]$sb.AppendLine('DEVICES ON THE NETWORK  (Random = randomized/private MAC, typical for phones)')
    [void]$sb.AppendLine(($devices | Sort-Object { [version]$_.IP } | Format-Table -AutoSize | Out-String -Width 200))
}
if ($procs) {
    [void]$sb.AppendLine('PROGRAMS ON THIS PC WITH THE MOST INTERNET CONNECTIONS')
    [void]$sb.AppendLine(($procs | Format-Table -AutoSize | Out-String -Width 200))
}
[void]$sb.AppendLine('NOT CHECKED FROM THE PC (look in the router admin page):')
[void]$sb.AppendLine('  - Router firmware updates; 5 GHz channel width (use 80 MHz) and 2.4 GHz width (use 20 MHz)')
[void]$sb.AppendLine('  - "Legacy"/802.11b compatibility mode (turn off), band steering, QoS/SQM, connected-device traffic statistics')
[void]$sb.AppendLine('  - Line status (DSL/cable sync rate, errors) if your router is also the modem')

$reportPath = Join-Path $OutputDir 'report.txt'
$sb.ToString() | Out-File -FilePath $reportPath -Encoding utf8
[pscustomobject]@{ Findings = $sorted; Data = $Data } | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $OutputDir 'report.json') -Encoding utf8

Write-Host "`n`nFINDINGS (most important first)" -ForegroundColor White
$colors = @{ High = 'Red'; Medium = 'Yellow'; Low = 'DarkYellow'; Info = 'Gray'; OK = 'Green' }
$i = 0
foreach ($f in $sorted) {
    $i++
    Write-Host ("{0}. [{1}] {2}: {3}" -f $i, $f.Severity, $f.Area, $f.Finding) -ForegroundColor $colors[$f.Severity]
    if ($f.Fix) { Write-Host "   Fix: $($f.Fix)" }
}
Write-Host "`nFull report: $reportPath" -ForegroundColor Cyan
Write-Host 'The report contains network names, MAC and IP addresses - share it only with people you trust.' -ForegroundColor DarkGray
