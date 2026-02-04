<#
.SYNOPSIS
  PCAP triage: scans a capture for common network symptoms and reports evidence + why it matters.

.PREREQS
  - Wireshark installed (tshark available in PATH), or provide -TsharkPath.

.USAGE
  .\ps_pcap_scanner.ps1 -PcapPath .\capture.pcapng
  .\ps_pcap_scanner.ps1 -PcapPath .\capture.pcapng -TopN 10 -SamplesPerIssue 5 -AckRttHighMs 250

.NOTES
  This does not "prove blame" (network vs app). It surfaces common symptoms and evidence frames.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory, Position=0)]
  [ValidateScript({ Test-Path $_ })]
  [string]$PcapPath,

  [int]$TopN = 10,
  [int]$SamplesPerIssue = 3,

  [int]$AckRttHighMs = 200,
  [int]$ZeroWindowMinCount = 5,
  [int]$ResetMinCount = 3,

  [string]$TsharkPath = "tshark"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Tshark {
  try {
    $null = & $TsharkPath -v 2>$null
  } catch {
    throw "tshark not found. Install Wireshark or pass -TsharkPath to tshark.exe."
  }
}

function Invoke-Tshark {
  param([Parameter(Mandatory)][string[]]$Args)
  # Capture stdout; ignore stderr warnings.
  & $TsharkPath @Args 2>$null
}

function Get-Count {
  param([Parameter(Mandatory)][string]$Filter)
  $args = @("-r", $PcapPath, "-Y", $Filter, "-T", "fields", "-e", "frame.number")
  $lines = Invoke-Tshark -Args $args
  if ($null -eq $lines) { return 0 }
  if ($lines -is [string]) { return 1 }
  return @($lines).Count
}

function Get-FrameSamples {
  param(
    [Parameter(Mandatory)][string]$Filter,
    [int]$Count = 3
  )

  $fields = @(
    "-T", "fields",
    "-E", "separator=|",
    "-e", "frame.number",
    "-e", "frame.time_relative",
    "-e", "ip.src",
    "-e", "tcp.srcport",
    "-e", "udp.srcport",
    "-e", "ip.dst",
    "-e", "tcp.dstport",
    "-e", "udp.dstport",
    "-e", "_ws.col.Protocol",
    "-e", "_ws.col.Info"
  )

  $args = @("-r", $PcapPath, "-Y", $Filter) + $fields
  $lines = Invoke-Tshark -Args $args | Select-Object -First $Count

  $samples = foreach ($line in $lines) {
    $p = $line -split "\|", -1
    if ($p.Count -lt 10) { continue }

    $srcPort = if ($p[3]) { $p[3] } elseif ($p[4]) { $p[4] } else { "" }
    $dstPort = if ($p[6]) { $p[6] } elseif ($p[7]) { $p[7] } else { "" }

    [pscustomobject]@{
      Frame  = $p[0]
      Time_s = $p[1]
      Src    = if ($srcPort) { "$($p[2]):$srcPort" } else { $p[2] }
      Dst    = if ($dstPort) { "$($p[5]):$dstPort" } else { $p[5] }
      Proto  = $p[8]
      Info   = $p[9]
    }
  }

  return $samples
}

function Get-AckRttHighCount {
  param([int]$ThresholdMs)

  $thresholdSec = [math]::Round($ThresholdMs / 1000.0, 6).ToString("0.######")
  $filter = "tcp.analysis.ack_rtt and tcp.analysis.ack_rtt > $thresholdSec"
  return @{
    Filter = $filter
    Count  = Get-Count -Filter $filter
  }
}

Assert-Tshark

$ackRtt = Get-AckRttHighCount -ThresholdMs $AckRttHighMs

$IssueChecks = @(
  @{
    Key    = "tcp_retrans"
    Name   = "TCP Retransmissions / Loss Indicators"
    Filter = "tcp.analysis.retransmission or tcp.analysis.fast_retransmission or tcp.analysis.spurious_retransmission or tcp.analysis.lost_segment"
    Why    = "Often indicates packet loss, congestion, or path issues. Can also be capture artifacts (SPAN drops) or sender-side delay."
    Hint   = "Look for bursts, specific flows, and whether RTT inflates at the same time."
  },
  @{
    Key    = "dup_ack"
    Name   = "TCP Duplicate ACKs"
    Filter = "tcp.analysis.duplicate_ack"
    Why    = "Duplicate ACKs commonly appear when segments go missing or arrive out-of-order. Often correlates with loss or reordering."
    Hint   = "Correlate with retransmissions and out-of-order events."
  },
  @{
    Key    = "out_of_order"
    Name   = "TCP Out-of-Order Segments"
    Filter = "tcp.analysis.out_of_order"
    Why    = "Can indicate path reordering (ECMP/load balancing) or capture timing issues. Excess can harm performance."
    Hint   = "If reordering is consistent and large, check ECMP/load balancers; if only at capture point, suspect SPAN/mirror drops."
  },
  @{
    Key      = "zero_window"
    Name     = "TCP Zero Window / Receiver Flow Control"
    Filter   = "tcp.analysis.zero_window or tcp.window_size_value == 0"
    Why      = "Receiver advertised it cannot accept more data (buffer pressure / app not reading). Usually endpoint/app-side more than the network."
    Hint     = "Check receiver CPU/memory, disk IO, and whether the app is slow to read."
    MinCount = $ZeroWindowMinCount
  },
  @{
    Key      = "resets"
    Name     = "TCP Resets (RST)"
    Filter   = "tcp.flags.reset == 1"
    Why      = "RST can mean app closed abruptly, port unreachable, middlebox interference, or firewall-injected resets."
    Hint     = "Identify which side sent the RST and whether it follows SYN or an established session."
    MinCount = $ResetMinCount
  },
  @{
    Key    = "syn_retrans"
    Name   = "SYN Retransmissions / Connection Establishment Trouble"
    Filter = "(tcp.flags.syn==1 and tcp.flags.ack==0) and tcp.analysis.retransmission"
    Why    = "Often indicates initial handshake packets not answered (firewall drop, host unreachable, service down, routing/ACL issue)."
    Hint   = "If many SYNs to same dst:port with no SYN/ACK, suspect reachability or filtering."
  },
  @{
    Key    = "dns_errors"
    Name   = "DNS Errors (NXDOMAIN / SERVFAIL / REFUSED)"
    Filter = "dns.flags.rcode != 0"
    Why    = "Name resolution failures can look like 'network down' to apps. Usually DNS/server-side, sometimes blocked UDP/53."
    Hint   = "Check which rcode is common and which resolver IP is replying."
  },
  @{
    Key    = "icmp_unreach"
    Name   = "ICMP Destination Unreachable"
    Filter = "icmp.type==3 or icmpv6.type==1"
    Why    = "Indicates routing/host/port unreachable conditions (for example, 'port unreachable' for UDP). Strong reachability signal."
    Hint   = "Inspect ICMP code to see host/network/port/admin-prohibited style failures."
  },
  @{
    Key    = "tls_alerts"
    Name   = "TLS Alerts / Handshake Problems"
    Filter = "tls.alert_message or ssl.alert_message"
    Why    = "TLS alerts can indicate cert/hostname issues, protocol mismatch, interception, or app misconfiguration."
    Hint   = "Look for alert descriptions like handshake_failure, unknown_ca, bad_certificate, protocol_version."
  },
  @{
    Key    = "arp_noise"
    Name   = "Excessive ARP Requests (Possible L2 reachability or broadcast noise)"
    Filter = "arp.opcode == 1"
    Why    = "Lots of ARP 'who-has' can indicate neighbors not responding, IP conflicts, or noisy broadcast domains."
    Hint   = "If ARP requests spike without ARP replies, investigate switching/VLAN/L2."
  },
  @{
    Key         = "high_rtt"
    Name        = "High TCP ACK RTT (Heuristic)"
    Filter      = $ackRtt.Filter
    Why         = "Elevated RTT increases latency and can trigger timeouts. Could be WAN distance, congestion, or endpoint delay."
    Hint        = "Tune threshold for your environment; compare flows and periods, not just totals."
    CustomCount = $ackRtt.Count
  }
)

$results = foreach ($issue in $IssueChecks) {
  $count = if ($issue.ContainsKey("CustomCount")) { [int]$issue.CustomCount } else { [int](Get-Count -Filter $issue.Filter) }
  $min   = if ($issue.ContainsKey("MinCount")) { [int]$issue.MinCount } else { 1 }
  $flag  = ($count -ge $min)

  [pscustomobject]@{
    Key     = $issue.Key
    Issue   = $issue.Name
    Count   = $count
    Flagged = $flag
    Filter  = $issue.Filter
    Why     = $issue.Why
    Hint    = $issue.Hint
    Min     = $min
  }
}

$ranked = $results | Where-Object { $_.Flagged -and $_.Count -gt 0 } | Sort-Object Count -Descending

if (-not $ranked) {
  Write-Host ""
  Write-Host "No strong matches found for the configured checks."
  Write-Host "That does NOT mean the capture is healthy; it means these heuristics did not trigger."
  Write-Host "Try lowering -AckRttHighMs or adding protocol-specific checks."
  exit 0
}

$top = $ranked | Select-Object -First $TopN

Write-Host ""
Write-Host "=== PCAP TRIAGE SUMMARY (Top $($top.Count)) ==="
$top | Select-Object Count, Issue, Key | Format-Table -AutoSize

foreach ($item in $top) {
  Write-Host ""
  Write-Host "=== $($item.Issue) ==="
  Write-Host ("Count: {0} (Minimum to flag: {1})" -f $item.Count, $item.Min)
  Write-Host "Why it matters: $($item.Why)"
  Write-Host "Heuristic note: $($item.Hint)"
  Write-Host "tshark filter: $($item.Filter)"

  $samples = Get-FrameSamples -Filter $item.Filter -Count $SamplesPerIssue
  if ($samples -and $samples.Count -gt 0) {
    Write-Host ""
    Write-Host "Evidence (sample frames):"
    $samples | Format-Table -AutoSize
    Write-Host "Interpretation:"
    switch ($item.Key) {
      "tcp_retrans"  { Write-Host "  - Retrans + lost segments suggest loss/congestion. If isolated to one flow, suspect that path/host." }
      "dup_ack"      { Write-Host "  - Duplicate ACKs suggest missing data or reordering; confirm with retrans/out-of-order near same time." }
      "out_of_order" { Write-Host "  - Out-of-order can be ECMP/LB reordering or capture artifacts; compare against capture method." }
      "zero_window"  { Write-Host "  - Zero window usually means receiver/app bottleneck (buffer full). Network is typically not primary." }
      "resets"       { Write-Host "  - RST sender matters: server RST can mean app closed; middleboxes/firewalls may inject too." }
      "syn_retrans"  { Write-Host "  - SYN retrans implies no SYN/ACK. Often firewall drop, service down, or routing/ACL issues." }
      "dns_errors"   { Write-Host "  - DNS errors can masquerade as network issues. Check rcode and resolver behavior." }
      "icmp_unreach" { Write-Host "  - ICMP unreachable codes can indicate true reachability failures or UDP port unreachable." }
      "tls_alerts"   { Write-Host "  - TLS alerts often point to cert/hostname/protocol mismatch or interception." }
      "arp_noise"    { Write-Host "  - Excess ARP can indicate L2 instability/noise. Check whether ARP replies are missing." }
      "high_rtt"     { Write-Host "  - High RTT increases latency/timeouts. Isolate by dst and time window; tune threshold." }
    }
  } else {
    Write-Host "No sample frames available for this filter."
  }
}

Write-Host ""
Write-Host "=== QUICK TAKEAWAY ==="
Write-Host "If retrans/dupACK/out-of-order dominate: likely loss/reordering (or capture loss)."
Write-Host "If zero-window dominates: likely receiver/app bottleneck."
Write-Host "If SYN retrans dominates: likely filtering/reachability/service down."
Write-Host "If DNS/TLS dominates: likely name resolution or security/config more than transport."
