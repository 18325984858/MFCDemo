<#
.SYNOPSIS
    在【虚拟机内部】运行,把虚拟机配置成与物理机同网段的静态 IP。

.DESCRIPTION
    物理机当前为 192.168.1.2/24,网关 192.168.1.1。
    本脚本将虚拟机设为同网段静态地址(默认 192.168.1.50/24)。
    需要以【管理员】身份运行 PowerShell。

    用法(在 VM 内,管理员 PowerShell):
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\vm-setup-network.ps1
    可选参数:
        .\vm-setup-network.ps1 -IPAddress 192.168.1.60
#>

[CmdletBinding()]
param(
    [string]$IPAddress  = '192.168.1.50',
    [int]   $PrefixLength = 24,            # 255.255.255.0
    [string]$Gateway    = '192.168.1.1',
    [string[]]$DnsServers = @('192.168.1.1', '8.8.8.8')
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '请以【管理员】身份运行 PowerShell 后重试。'
    }
}

function Get-ActiveAdapter {
    # 选择已启用、非回环、非虚拟隔离的、当前有连接的网卡
    $candidates = Get-NetAdapter -Physical |
        Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch 'Loopback' }

    if (-not $candidates) {
        # 退而求其次:任意已启用网卡
        $candidates = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    }

    if (-not $candidates) {
        throw '未找到处于 Up 状态的网卡,请确认虚拟机网络已连接(桥接模式)。'
    }

    # 若有多块,优先选有默认网关或流量最多的那块
    $best = $candidates | Sort-Object -Property InterfaceIndex | Select-Object -First 1
    return $best
}

Assert-Admin

Write-Host '== 当前网络配置 ==' -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' } |
    Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize

$adapter = Get-ActiveAdapter
$ifIndex = $adapter.InterfaceIndex
Write-Host ("选用网卡: {0} (Index {1})" -f $adapter.Name, $ifIndex) -ForegroundColor Yellow

# 清除旧的 IPv4 地址与网关,避免冲突
Write-Host '清除旧 IPv4 地址 / 网关 ...' -ForegroundColor DarkGray
Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

# 设置静态 IP + 网关
Write-Host ("设置静态 IP: {0}/{1}  网关 {2}" -f $IPAddress, $PrefixLength, $Gateway) -ForegroundColor Green
New-NetIPAddress -InterfaceIndex $ifIndex `
    -IPAddress $IPAddress `
    -PrefixLength $PrefixLength `
    -DefaultGateway $Gateway | Out-Null

# 设置 DNS
Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $DnsServers

Write-Host ''
Write-Host '== 配置后网络 ==' -ForegroundColor Cyan
Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 |
    Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize

Write-Host ''
Write-Host '== 连通性自检(ping 网关 / 物理机)==' -ForegroundColor Cyan
foreach ($target in @($Gateway, '192.168.1.2')) {
    $ok = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction SilentlyContinue
    $status = if ($ok) { 'OK   ' } else { 'FAIL ' }
    $color  = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  ping {0}  ->  {1}" -f $target, $status) -ForegroundColor $color
}

Write-Host ''
Write-Host '完成。若 ping 物理机失败,请检查 VMware 虚拟网络编辑器中 VMnet0 是否桥接到主机【真正联网的物理网卡】。' -ForegroundColor Yellow
