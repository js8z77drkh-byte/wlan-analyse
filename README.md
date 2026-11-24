# wlan-analyse

Finds what is slowing down your Wi-Fi, from a Windows PC that is connected to it.
Read-only: nothing on the PC or router is changed, and no router password is needed.

## Run it

1. Download this repo (Code > Download ZIP) and unzip it on the Windows PC.
2. Connect the PC to the Wi-Fi you want to check. Unplug any LAN cable. Stop big downloads.
3. Double-click **`Run-WlanAnalyse.cmd`**. It takes about 1-2 minutes.
4. Read the findings, most important first. The full report is in `report-<date>\report.txt`.

Options (from PowerShell): `.\wlan-analyse.ps1 -NoSpeedTest -NoSweep`

> **Windows 11:** If it says Location access is off, turn on
> Settings > Privacy & security > Location > *Location services* and
> *Let desktop apps access your location*. Windows needs this to show Wi-Fi details.

## What it checks

| Area | Check |
|---|---|
| Wi-Fi link | Signal (% and dBm), band 2.4/5/6 GHz, Wi-Fi standard, link rate, WEP/TKIP security |
| Neighbours | Networks overlapping your channel, best 2.4 GHz channel (1/6/11), least used 5 GHz block, channel utilisation reported by the router |
| Roaming | 5 GHz of your network available but PC on 2.4 GHz, stronger mesh node ignored |
| Latency | Ping to the router vs the internet: separates **Wi-Fi problems** from **internet line problems** |
| Speed | Download speed (speed.cloudflare.com) compared to what the Wi-Fi link can carry |
| Bufferbloat | Latency while the line is busy (lag during calls/games when someone downloads) |
| DNS | Response time of your DNS server vs 1.1.1.1 |
| Adapter | Driver age, Wi-Fi power saving, preferred band, channel width limits |
| Network | Devices on the network, VPNs, background sync programs |

The router's own settings (firmware, channel width, QoS) need its admin login; the
report lists what to look at there.

## Privacy

The report contains network names, MAC and IP addresses of devices in your home.
`report-*` folders are git-ignored. The script contacts `1.1.1.1`, `8.8.8.8`, and
`speed.cloudflare.com` (skip the last with `-NoSpeedTest`).
