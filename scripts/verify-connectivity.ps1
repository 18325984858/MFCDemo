<#
.SYNOPSIS
    联调验证:检查与对端主机的 ping 连通性,以及 NetDrv 项目使用的 TCP 端口是否可达。

.DESCRIPTION
    端口取自 Shared/Protocol.h:
        UDP  9999  (legacy UDP)        9998 (screen agent)
        TCP 10000  (control / primary)
        TCP 10001  (screen)
        TCP 10002  (file)
    注意:UDP 为无连接,无法用 TcpClient 探测;此脚本仅对 TCP 端口做连通性测试,
    并对 UDP 端口尝试发送探测包(不保证有响应)。

    在【物理机】运行时,-Target 填虚拟机 IP;
    在【虚拟机】运行时,-Target 填物理机 IP(192.168.1.2)。

    用法:
        .\verify-connectivity.ps1 -Target 192.168.1.50
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [int[]]$TcpPorts = @(10000, 10001, 10002),
    [int[]]$UdpPorts = @(9999, 9998),
    [int]  $TimeoutMs = 1500
)

function Test-TcpPort {
    param([string]$TargetHost, [int]$Port, [int]$TimeoutMs)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $client.Connected) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

Write-Host ("== Ping {0} ==" -f $Target) -ForegroundColor Cyan
$ping = Test-Connection -ComputerName $Target -Count 3 -Quiet -ErrorAction SilentlyContinue
if ($ping) {
    Write-Host '  ICMP ping  ->  OK' -ForegroundColor Green
} else {
    Write-Host '  ICMP ping  ->  FAIL  (检查同网段/防火墙/桥接)' -ForegroundColor Red
}

Write-Host ''
Write-Host '== TCP 端口连通性 ==' -ForegroundColor Cyan
foreach ($p in $TcpPorts) {
    $ok = Test-TcpPort -TargetHost $Target -Port $p -TimeoutMs $TimeoutMs
    $status = if ($ok) { 'OPEN  ' } else { 'CLOSED' }
    $color  = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  tcp/{0}  ->  {1}" -f $p, $status) -ForegroundColor $color
}

Write-Host ''
Write-Host '== UDP 端口探测(无连接,仅发送,不保证响应)==' -ForegroundColor Cyan
foreach ($p in $UdpPorts) {
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $bytes = [Text.Encoding]::ASCII.GetBytes('NDR2-PROBE')
        [void]$udp.Send($bytes, $bytes.Length, $Target, $p)
        $udp.Close()
        Write-Host ("  udp/{0}  ->  探测包已发送" -f $p) -ForegroundColor DarkGray
    } catch {
        Write-Host ("  udp/{0}  ->  发送失败: {1}" -f $p, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host '提示:TCP 端口显示 CLOSED 通常表示对端 NetDrv 驱动/服务未在监听,属正常(未启动时)。' -ForegroundColor Yellow
