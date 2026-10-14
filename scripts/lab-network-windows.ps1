param(
    [Parameter(Mandatory)][ValidateSet('apply','rollback','status')][string]$Action,
    [Parameter(Mandatory)][string]$Journal,
    [string]$Config
)
$ErrorActionPreference='Stop'
# This helper is intentionally unavailable on an ordinary workstation. No VM
# detector is implied: these flags are an explicit deployment boundary.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:CONNECT_IP_LAB_VM -ne '1') { throw 'Network helper is restricted to an explicitly opted-in disposable CI VM' }
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated lab helper required'}
$Journal=[IO.Path]::GetFullPath($Journal)
New-Item -ItemType Directory -Force (Split-Path -Parent $Journal) | Out-Null
$lock=[IO.File]::Open($Journal+'.lock',[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
function Save-Journal {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($script:state | ConvertTo-Json -Depth 20))
    $temporary=$Journal+'.new'
    $file=[IO.File]::Open($temporary,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    if(Test-Path -LiteralPath $Journal){[IO.File]::Replace($temporary,$Journal,[NullString]::Value)}else{[IO.File]::Move($temporary,$Journal)}
}
function Undo-Lab {
    if($state.id -notmatch '^CONNECT-LAB-[0-9a-f]{32}$' -or $state.interface -notmatch '^ccip[a-zA-Z0-9-]{1,11}$' -or $state.ip -ne '10.231.0.2'){throw 'Invalid journal ownership'}
    foreach($name in @($state.firewall_attempted)){if($name -notmatch ('^'+$state.id+'-(ipv4|ipv6|endpoint-tcp|endpoint-other-udp|service-outside-tun)$')){throw 'Foreign firewall rule in journal'}}
    foreach($prefix in @($state.routes_attempted)){if($prefix -ne '10.232.0.1/32'){throw 'Foreign route in journal'}}
    # Validate the complete restore plan before any guard can be removed.
    if($state.before.mtu -lt 576 -or $state.before.mtu -gt 65535 -or $state.before.metric -lt 0 -or $state.before.metric -gt 9999 -or $state.before.dad -lt 0 -or $state.before.dad -gt 255 -or $state.before.dhcp -notin @('Enabled','Disabled') -or $state.before.automatic_metric -notin @('Enabled','Disabled')){throw 'Invalid interface restore snapshot'}
    foreach($profile in @($state.before.profiles)){if($profile.name -notin @('Domain','Private','Public') -or $profile.enabled -notin @('True','False','NotConfigured')){throw 'Invalid firewall profile snapshot'}}
    foreach($address in @($state.before.dns)){ $parsedAddress=$null; if(-not [Net.IPAddress]::TryParse($address,[ref]$parsedAddress)){throw 'Invalid DNS restore snapshot'} }
    # Firewall guards are removed LAST. A missing/deleted adapter is normal after
    # process death. A reused name with a different GUID is never reconfigured.
    $adapter=Get-NetAdapter -Name $state.interface -ErrorAction SilentlyContinue
    if($adapter -and $adapter.InterfaceGuid.ToString() -ne $state.guid){throw 'Adapter identity changed; retain guard and resolve journal manually'}
    if($adapter){
        if($state.dns_attempted){
            if(@($state.before.dns).Count){Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($state.before.dns)}else{Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses}
        }
        foreach($prefix in @($state.routes_attempted)){Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false}
        if($state.address_attempted){Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $state.ip -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false}
        if($state.interface_attempted){Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -NlMtuBytes $state.before.mtu -InterfaceMetric $state.before.metric -AutomaticMetric $state.before.automatic_metric -DadTransmits $state.before.dad -Dhcp $state.before.dhcp}
    }
    # Remove exactly our NRPT identifier, not all rules sharing a namespace.
    if($state.nrpt_name){Get-DnsClientNrptRule -Name $state.nrpt_name -ErrorAction SilentlyContinue | Where-Object Comment -eq $state.id | Remove-DnsClientNrptRule -Force}
    elseif($state.nrpt_attempted){Get-DnsClientNrptRule | Where-Object Comment -eq $state.id | Remove-DnsClientNrptRule -Force}
    foreach($name in @($state.firewall_attempted)){Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule}
    if($state.profiles_attempted){foreach($profile in @($state.before.profiles)){Set-NetFirewallProfile -Profile $profile.name -Enabled $profile.enabled}}
    $state.phase='rolled-back';Save-Journal
}
function Close-OutsideLabTCP([string]$endpoint){
    # Existing TCP flows can send one last data packet during firewall
    # reauthorization. This disruptive step belongs ONLY to a disposable CI VM.
    if(-not ('ConnectLabTcp' -as [type])){
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class ConnectLabTcp {
 [StructLayout(LayoutKind.Sequential)]
 public struct Row { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort; }
 [DllImport("iphlpapi.dll", ExactSpelling=true)]
 public static extern uint SetTcpEntry(ref Row row);
}
'@
    }
    function Outside-TCP {
        Get-NetTCPConnection | Where-Object {
            $remote=[Net.IPAddress]::Parse($_.RemoteAddress)
            if($remote.IsIPv4MappedToIPv6){$remote=$remote.MapToIPv4()}
            $_.State.ToString() -notin @('Listen','Bound','Closed','TimeWait','DeleteTCB') -and -not [Net.IPAddress]::IsLoopback($remote) -and $remote.ToString() -notin @($endpoint,'10.232.0.1')
        }
    }
    $state.tcp_reset_attempted=$true;Save-Journal
    for($pass=0;$pass -lt 3;$pass++){
        $outside=@(Outside-TCP)
        if(-not $outside.Count){return}
        foreach($connection in $outside){
            $local=[Net.IPAddress]::Parse($connection.LocalAddress);$remote=[Net.IPAddress]::Parse($connection.RemoteAddress)
            if($local.IsIPv4MappedToIPv6){$local=$local.MapToIPv4()};if($remote.IsIPv4MappedToIPv6){$remote=$remote.MapToIPv4()}
            if($local.AddressFamily -ne 'InterNetwork' -or $remote.AddressFamily -ne 'InterNetwork'){throw 'Existing external IPv6 flow cannot be closed by the lab helper; refuse setup'}
            $row=[ConnectLabTcp+Row]::new();$row.State=12
            $row.LocalAddress=[BitConverter]::ToUInt32($local.GetAddressBytes(),0);$row.RemoteAddress=[BitConverter]::ToUInt32($remote.GetAddressBytes(),0)
            $row.LocalPort=(([uint32]$connection.LocalPort -band 255) -shl 8) -bor ([uint32]$connection.LocalPort -shr 8)
            $row.RemotePort=(([uint32]$connection.RemotePort -band 255) -shl 8) -bor ([uint32]$connection.RemotePort -shr 8)
            $state.tcp_reset_targets+=@{local=$local.ToString();local_port=$connection.LocalPort;remote=$remote.ToString();remote_port=$connection.RemotePort};Save-Journal
            $code=[ConnectLabTcp]::SetTcpEntry([ref]$row)
            if($code -ne 0){
                $remaining=@(Outside-TCP | Where-Object {$_.LocalAddress -eq $connection.LocalAddress -and $_.LocalPort -eq $connection.LocalPort -and $_.RemoteAddress -eq $connection.RemoteAddress -and $_.RemotePort -eq $connection.RemotePort})
                if($remaining.Count){throw ('Unable to close existing direct TCP flow, Win32 error '+$code)}
            }
        }
    }
    if(@(Outside-TCP).Count){throw 'Existing direct TCP flows remain; refuse setup'}
}
try {
    if($Action -eq 'status'){Get-Content -LiteralPath $Journal -Raw;return}
    if($Action -eq 'rollback'){
        $script:state=Get-Content -LiteralPath $Journal -Raw | ConvertFrom-Json
        if($state.journal_version -ne 1){throw 'Unsupported network journal'}
        if($state.phase -ne 'rolled-back'){Undo-Lab}
        return
    }
    if(Test-Path -LiteralPath $Journal){throw 'Journal already exists; rollback/reconcile it before a new apply'}
    $cfg=Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
    if($cfg.config_version -ne 2 -or $cfg.environment -ne 'isolated-lab' -or $cfg.interface -notmatch '^ccip[a-zA-Z0-9-]{1,11}$'){throw 'Requires a lab profile and newly-created ccip interface'}
    # This conservative first helper permits the generated lab topology only.
    # Arbitrary profiles cannot turn it into a general elevated network editor.
    if($cfg.device_ip -ne '10.231.0.2' -or @($cfg.destinations).Count -ne 1 -or $cfg.destinations[0] -ne '10.232.0.1/32'){throw 'Unsupported lab network plan'}
    if($cfg.endpoint -notmatch '^(127\.0\.0\.1|192\.168\.231\.1):([1-9][0-9]{0,4})$'){throw 'Unsupported lab endpoint'}
    $endpoint=$Matches[1];$port=[int]$Matches[2];if($port -gt 65535){throw 'Invalid endpoint port'}
    $adapter=Get-NetAdapter -Name $cfg.interface
    # The parent creates Wintun before invoking the helper. Refuse any adapter
    # with an existing usable IPv4 address or target route instead of overwriting.
    $existing=@(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -notlike '169.254.*')
    if($existing.Count -ne 0 -or (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '10.232.0.1/32' -ErrorAction SilentlyContinue)){throw 'Target adapter is not a fresh lab interface'}
    if(Get-DnsClientNrptRule | Where-Object {$_.Namespace -contains '.test'}){throw 'Existing .test DNS policy; refusing to replace it'}
    $ipif=Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
    $dns=@((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses)
    $id='CONNECT-LAB-'+[guid]::NewGuid().ToString('N')
    $profiles=@(Get-NetFirewallProfile | ForEach-Object {@{name=$_.Name.ToString();enabled=$_.Enabled.ToString()}})
    $script:state=[pscustomobject]@{journal_version=1;id=$id;interface=$cfg.interface;guid=$adapter.InterfaceGuid.ToString();ip=$cfg.device_ip;phase='applying';before=@{profiles=$profiles;dns=$dns;mtu=$ipif.NlMtu;metric=$ipif.InterfaceMetric;automatic_metric=$ipif.AutomaticMetric.ToString();dad=$ipif.DadTransmits;dhcp=$ipif.Dhcp.ToString()};profiles_attempted=$false;firewall_attempted=@();routes_attempted=@();address_attempted=$false;interface_attempted=$false;dns_attempted=$false;nrpt_attempted=$false;nrpt_name=$null;tcp_reset_attempted=$false;tcp_reset_targets=@()}
    Save-Journal
    try{
        $state.profiles_attempted=$true;Save-Journal
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        function Add-Guard([string]$suffix,[hashtable]$ruleOptions){
            $name=$state.id+'-'+$suffix;$state.firewall_attempted+=,$name;Save-Journal
            try{New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -Profile Any -PolicyStore PersistentStore @ruleOptions | Out-Null}catch{throw ('Guard '+$suffix+' failed: '+$_.Exception.Message)}
        }
        # Block all IPv4 except the endpoint and lab service, across every NIC.
        # Explicit private ranges avoid CIDR arithmetic and exclude only exact IPs.
        if($endpoint -eq '127.0.0.1'){$remote=@('0.0.0.0-10.232.0.0','10.232.0.2-127.0.0.0','127.0.0.2-255.255.255.255')}
        else{$remote=@('0.0.0.0-10.232.0.0','10.232.0.2-192.168.231.0','192.168.231.2-255.255.255.255')}
        Add-Guard 'ipv4' @{RemoteAddress=$remote}
        # NetSecurity rejects the zero-length IPv6 prefix on this Windows image.
        # Two /1 prefixes cover the same complete 128-bit address space.
        Add-Guard 'ipv6' @{RemoteAddress=@('::/1','8000::/1')}
        # Loopback 17445 is the disposable QEMU serial controller, not Core IPC.
        $tcpPorts=if($endpoint -eq '127.0.0.1'){@('1-17444','17446-65535')}else{@('1-65535')}
        Add-Guard 'endpoint-tcp' @{RemoteAddress=$endpoint;Protocol='TCP';RemotePort=$tcpPorts}
        $ports=@();if($port -gt 1){$ports+=('1-'+($port-1))};if($port -lt 65535){$ports+=(($port+1).ToString()+'-65535')}
        Add-Guard 'endpoint-other-udp' @{RemoteAddress=$endpoint;Protocol='UDP';RemotePort=$ports}
        # A lab service must not become reachable via a physical/default route
        # after the TUN disappears. Inventory every existing alternate adapter.
        $connected=@(Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected')
        $visible=@(Get-NetAdapter | Where-Object {$_.ifIndex -in $connected.InterfaceIndex})
        $unknown=@($connected | Where-Object {$_.InterfaceAlias -notin $visible.Name -and $_.InterfaceAlias -notlike '*Loopback*'})
        if($unknown.Count){throw 'Connected hidden interface cannot be guarded by this lab helper'}
        $others=@($visible | Where-Object {$_.InterfaceGuid -ne $adapter.InterfaceGuid -and $_.Name -notlike '*Loopback*'} | Select-Object -ExpandProperty Name)
        if($others.Count){Add-Guard 'service-outside-tun' @{RemoteAddress='10.232.0.1';InterfaceAlias=$others}}
        Close-OutsideLabTCP $endpoint
        $state.interface_attempted=$true;Save-Journal
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -NlMtuBytes 1100 -Dhcp Disabled -DadTransmits 0 -InterfaceMetric 5
        $state.address_attempted=$true;Save-Journal
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $cfg.device_ip -PrefixLength 32 -PolicyStore ActiveStore | Out-Null
        $state.routes_attempted+=,'10.232.0.1/32';Save-Journal
        New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '10.232.0.1/32' -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore | Out-Null
        $state.dns_attempted=$true;Save-Journal
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses '10.232.0.1'
        $state.nrpt_attempted=$true;Save-Journal
        $rule=Add-DnsClientNrptRule -Namespace '.test' -NameServers '10.232.0.1' -Comment $id -PassThru
        $state.nrpt_name=$rule.Name;Save-Journal
        $state.phase='active';Save-Journal
    }catch{
        $original=$_
        try{Undo-Lab}catch{Write-Warning 'Rollback incomplete: retain journal, do not treat networking as restored; discard the disposable CI VM'}
        throw $original
    }
}finally{$lock.Dispose()}
