# Real Windows system VPN -> independent Linux kernel, only in disposable CI.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'This network test is restricted to a disposable CI VM'}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$boot=Join-Path $root 'vm-boot';$out=Join-Path $root 'desktop-vm-artifacts';$dist=Join-Path $root 'dist'
New-Item $out -ItemType Directory -Force | Out-Null
$installer=Join-Path $out 'qemu-setup.exe'
Invoke-WebRequest 'https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe' -OutFile $installer -TimeoutSec 120
$expected='5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543'
if((Get-FileHash $installer -Algorithm SHA512).Hash.ToLower() -ne $expected){throw 'QEMU supplier hash mismatch'}
$install=Start-Process $installer -ArgumentList '/S' -PassThru -Wait -WindowStyle Hidden
if($install.ExitCode){throw 'QEMU install failed'}
foreach($name in 'vmlinuz','rootfs.cpio.gz'){$entry=Get-Content (Join-Path $boot 'boot-sha256.txt') | Where-Object { $_.EndsWith('/'+$name) };if(!$entry -or (Get-FileHash (Join-Path $boot $name)).Hash.ToLower() -ne $entry.Split(' ')[0]){throw 'Guest boot hash mismatch'}}
Add-Type @'
using System;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Diagnostics;
public sealed class CorePipe {
 public Process Process;
 public volatile uint State,Code,Mode;
 public ulong TX,RX,Elapsed,DNS;
 public bool Ended;
 public Task<string> Errors;
 private readonly object gate=new object();
 private Stream input;
 public CorePipe(string exe,string appData) {
  Directory.CreateDirectory(appData);
  var info=new ProcessStartInfo(exe);info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardInput=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;info.ArgumentList.Add("--ipc");info.Environment["LOCALAPPDATA"]=appData;
  Process=Process.Start(info);input=Process.StandardInput.BaseStream;
  Task.Run(()=>{var output=Process.StandardOutput.BaseStream;try{while(true){byte[] h=Read(output,8);if(h[0]!=67||h[1]!=67||h[2]!=2||h[3]!=128||BitConverter.ToUInt32(h,4)!=176)throw new IOException("Invalid typed status");byte[] b=Read(output,176);lock(gate){Code=BitConverter.ToUInt32(b,4);TX=BitConverter.ToUInt64(b,8);RX=BitConverter.ToUInt64(b,16);Elapsed=BitConverter.ToUInt64(b,24);Mode=BitConverter.ToUInt32(b,32);DNS=BitConverter.ToUInt64(b,168);State=BitConverter.ToUInt32(b,0);}}}catch{Ended=true;}});
  Errors=Process.StandardError.ReadToEndAsync();
 }
 private static byte[] Read(Stream s,int n){byte[] b=new byte[n];int at=0;while(at<n){int got=s.Read(b,at,n-at);if(got==0)throw new EndOfStreamException();at+=got;}return b;}
 public void Send(byte kind,string data=""){byte[] p=Encoding.UTF8.GetBytes(data);byte[] h={67,67,2,kind,0,0,0,0};BitConverter.GetBytes((uint)p.Length).CopyTo(h,4);lock(gate){input.Write(h);input.Write(p);input.Flush();}}
 public string Status(){lock(gate){return $"state={State} code={Code} mode={Mode} tx={TX} rx={RX} dns_us={DNS}";}}
}
'@
function StartGuest([string]$exe,[string[]]$arguments){$i=[Diagnostics.ProcessStartInfo]::new($exe);$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardError=$true;foreach($a in $arguments){$i.ArgumentList.Add($a)};return [Diagnostics.Process]::Start($i)}
function AwaitGuest([string]$pattern,[int]$seconds=90){$deadline=[DateTime]::UtcNow.AddSeconds($seconds);while([DateTime]::UtcNow -lt $deadline){if($script:lineTask.IsCompleted){$line=$script:lineTask.GetAwaiter().GetResult();if($null -eq $line){throw 'Guest serial ended'};$script:guestLines.Add($line);$script:lineTask=$script:guestReader.ReadLineAsync();if($line -match $pattern){return};continue};Start-Sleep -Milliseconds 20};throw "Guest deadline: $pattern"}
# CI-only forensics cleanup: removing these own filters cannot make a failed
# recovery pass. No product client or privileged helper exposes this operation.
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class FailedCIGuard {
 [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
 public static void RemoveOwnDenyForEvidence(){IntPtr e;if(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out e)!=0)throw new Exception("CI forensic engine failed");try{for(int i=0;i<18;i++){byte[] b=new Guid("304497e9-426e-4f42-8a25-3a88525e71c0").ToByteArray();b[15]=(byte)(0xc1+i);Guid key=new Guid(b);uint code=FwpmFilterDeleteByKey0(e,ref key);if(code!=0&&code!=0x80320003)throw new Exception("CI own filter cleanup failed "+code);}Guid sub=new Guid("304497e9-426e-4f42-8a25-3a88525e71c0");uint removed=FwpmSubLayerDeleteByKey0(e,ref sub);if(removed!=0&&removed!=0x80320007)throw new Exception("CI own sublayer cleanup failed "+removed);}finally{FwpmEngineClose0(e);}}
}
'@
function RecoverWithDeadline {
 $recovery=Start-Process (Join-Path $dist 'ConnectCoreNetwork.exe') -ArgumentList '--recover' -WindowStyle Hidden -PassThru
 if(!$recovery.WaitForExit(15000)){$recovery.Kill();$recovery.WaitForExit();return $false}
 return $recovery.ExitCode -eq 0
}
function ReceiveCapture([string]$path){
 $offset=$guestLines.Count;$guestWriter.WriteLine('capture');AwaitGuest '^LAB_PCAP_END$' 180
 $lines=$guestLines.GetRange($offset,$guestLines.Count-$offset)
 $begin=$lines.IndexOf('LAB_PCAP_BEGIN');$end=$lines.IndexOf('LAB_PCAP_END')
 if($begin -lt 0 -or $end -le $begin){throw 'Invalid guest capture framing'}
 $bytes=[Convert]::FromBase64String(($lines.GetRange($begin+1,$end-$begin-1) -join ''))
 $hash=@($lines | Where-Object {$_ -match '^LAB_PCAP_SHA256 [0-9a-f]{64}$'})
 if($hash.Count -ne 1 -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLower() -ne $hash[0].Substring(16)){throw 'Guest capture hash mismatch'}
 [IO.File]::WriteAllBytes($path,$bytes)
}
function AwaitCore([uint32]$state,[int]$seconds=40){$deadline=[DateTime]::UtcNow.AddSeconds($seconds);while([DateTime]::UtcNow -lt $deadline){if($client.State -eq $state){Write-Output $client.Status();return};if($client.Process.HasExited){throw 'Core exited'};if($client.State -eq 4 -and $state -eq 3){throw ('Core failed: '+$client.Status())};Start-Sleep -Milliseconds 50};throw ('Core state deadline: '+$client.Status())}
$client=$null;$vm=$null;$listener=$null;$serial=$null;$capture=$false;$passed=$false
$guestLines=[Collections.Generic.List[string]]::new()
try{
 $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,17445);$listener.Start();$accept=$listener.AcceptTcpClientAsync()
 $qemu=Join-Path ${env:ProgramFiles} 'qemu/qemu-system-x86_64.exe'
 $vm=StartGuest $qemu @('-machine','q35','-accel','tcg,thread=multi','-smp','2','-m','768','-display','none','-monitor','none','-chardev','socket,id=control,host=127.0.0.1,port=17445','-serial',('file:'+(Join-Path $out 'linux-kernel.log')),'-serial','chardev:control','-no-reboot','-kernel',(Join-Path $boot 'vmlinuz'),'-initrd',(Join-Path $boot 'rootfs.cpio.gz'),'-append','console=ttyS0 rdinit=/init connect_lab_vm=1 panic=1','-netdev','user,id=lab,hostfwd=udp:127.0.0.1:17444-:17444','-device','virtio-net-pci,netdev=lab')
 $qemuErrors=$vm.StandardError.ReadToEndAsync()
 if(!$accept.Wait(10000)){throw 'Guest serial unavailable'};$serial=$accept.GetAwaiter().GetResult();$listener.Stop()
 $guestReader=[IO.StreamReader]::new($serial.GetStream());$guestWriter=[IO.StreamWriter]::new($serial.GetStream(),[Text.UTF8Encoding]::new($false));$guestWriter.AutoFlush=$true;$guestWriter.NewLine="`n";$lineTask=$guestReader.ReadLineAsync()
 AwaitGuest '^LAB_SERVER_READY$' 180
 # Inventory only current NICs, BEFORE our Wintun is created; capture never
 # includes the plaintext inner tunnel adapter or generic stack components.
 $components=@();$list=pktmon list --include-hidden;$list | Set-Content (Join-Path $out 'physical-components.log')
 foreach($line in $list){if($line -match '^\s*([0-9]+)\s+(.+)$'){$components+=[int]$Matches[1]}}
 if(!$components.Count){throw 'No physical capture components'}
 Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex | ConvertTo-Json | Set-Content (Join-Path $out 'before-adapters.json')
 pktmon start --capture --comp $components --pkt-size 0 --file-name (Join-Path $out 'physical.etl') | Out-Null
 if($LASTEXITCODE){throw 'NIC capture failed'};$capture=$true
 # Establish that this selected physical capture sees real pre-VPN traffic.
 Invoke-WebRequest 'https://www.wintun.net/' -TimeoutSec 30 -OutFile (Join-Path $out 'capture-baseline.html')
 $cfg=Get-Content (Join-Path $boot 'lab/ip-client.json') -Raw | ConvertFrom-Json
 foreach($field in 'ca','cert','key'){$cfg.trust.$field=Join-Path $boot ('lab/'+[IO.Path]::GetFileName($cfg.trust.$field))}
 $cfg.destinations=@('0.0.0.0/0');$cfg | Add-Member -NotePropertyName network -NotePropertyValue ([pscustomobject]@{mode='system-vpn';dns='10.232.0.1'})
 $profile=Join-Path $out 'private-client.json';$cfg | ConvertTo-Json -Depth 10 | Set-Content $profile -Encoding utf8NoBOM
 $client=[CorePipe]::new((Join-Path $dist 'connect-desktop-core.exe'),(Join-Path $out 'private-profile'))
 netsh wfp set options netevents=on | Out-Null
 $client.Send(1,$profile);AwaitCore 1 10;$client.Send(2);AwaitCore 3
 if($client.Mode -ne 1){throw 'System Wintun mode not active'}
 Write-Output 'REAL_WINDOWS_WINTUN_SYSTEM_ROUTES_READY'
 Find-NetRoute -RemoteIPAddress 10.232.0.1 | Format-List | Out-String | Set-Content (Join-Path $out 'selected-route.log')
 $client.Send(4);Start-Sleep -Seconds 4;$client.Status() | Set-Content (Join-Path $out 'initial-dns-status.log')
 python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'measurements.json')
 if($LASTEXITCODE){throw 'Real cross-kernel TCP/UDP/DNS failed'}
 python -c "import socket,time; r=socket.getaddrinfo('probe'+str(time.time_ns())+'.test',80,socket.AF_INET); assert r and all(x[4][0]=='10.232.0.1' for x in r); print('Windows system DNS traversed real Linux DNS')"
 if($LASTEXITCODE){throw 'System resolver bypassed tunnel'}
 $client.Send(4);$deadline=[DateTime]::UtcNow.AddSeconds(5);do{Start-Sleep -Milliseconds 50}while(!$client.DNS -and [DateTime]::UtcNow -lt $deadline)
 if(!$client.DNS -or !$client.TX -or !$client.RX){throw 'Actual DNS RTT / inner IP counters unavailable'}
 $client.Status() | Set-Content (Join-Path $out 'verified-core-status.log')
 $guestWriter.WriteLine('stop-server');AwaitGuest '^LAB_SERVER_STOPPED$';AwaitCore 4 35
 python "$PSScriptRoot/ip-lab-services.py" failure | Set-Content (Join-Path $out 'server-failure.log');if($LASTEXITCODE){throw 'Transport failure fell back direct'}
 python "$PSScriptRoot/vm-negative-probes.py" | Set-Content (Join-Path $out 'failed-transport-probes.json');if($LASTEXITCODE){throw 'Failed transport exposed direct network'}
 # Kill only this worker; persistent WFP must cover the removed TUN as well.
 $client.Process.Kill();$client.Process.WaitForExit();Start-Sleep -Seconds 2
 python "$PSScriptRoot/vm-negative-probes.py" | Set-Content (Join-Path $out 'crash-probes.json');if($LASTEXITCODE){throw 'Worker crash exposed direct network'}
 if(!(RecoverWithDeadline)){throw 'Explicit privileged recovery failed'}
 Write-Output 'TRANSPORT_AND_WORKER_CRASH_FAIL_CLOSED_AND_RECOVERY_PASSED'
 $guestWriter.WriteLine('start-server');AwaitGuest '^LAB_SERVER_READY$'
 $client=[CorePipe]::new((Join-Path $dist 'connect-desktop-core.exe'),(Join-Path $out 'private-profile'))
 AwaitCore 1 10;$client.Send(2);AwaitCore 3
 python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'reconnect-measurements.json');if($LASTEXITCODE){throw 'Fresh session after recovery failed'}
 # Crash this session's authenticated helper while keeping Core alive. Its
 # dynamic permits must disappear and persistent deny must cover the lost TUN.
 $helperPath=(Resolve-Path (Join-Path $dist 'ConnectCoreNetwork.exe')).Path
 $helpers=@(Get-CimInstance Win32_Process -Filter "Name='ConnectCoreNetwork.exe'" | Where-Object {$_.ExecutablePath -eq $helperPath -and $_.CommandLine -match (' '+$client.Process.Id+'$')})
 if($helpers.Count -ne 1){throw 'Owned network helper could not be identified uniquely'}
 Stop-Process -Id $helpers[0].ProcessId -Force;AwaitCore 4 10
 python "$PSScriptRoot/ip-lab-services.py" failure | Set-Content (Join-Path $out 'helper-failure.log');if($LASTEXITCODE){throw 'Helper crash fell back direct'}
 python "$PSScriptRoot/vm-negative-probes.py" | Set-Content (Join-Path $out 'helper-crash-probes.json');if($LASTEXITCODE){throw 'Helper crash exposed direct network'}
 $client.Send(8);AwaitCore 1 15;$client.Send(2);AwaitCore 3
 python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'helper-recovery-measurements.json');if($LASTEXITCODE){throw 'Client-command recovery failed'}
 Write-Output 'HELPER_CRASH_AND_CLIENT_IPC_RECOVERY_PASSED'
 $client.Send(3);AwaitCore 1 10;$client.Send(5);if(!$client.Process.WaitForExit(10000)){throw 'Worker shutdown hung'}
 $deadline=[DateTime]::UtcNow.AddSeconds(5);do{$remaining=@(Get-CimInstance Win32_Process -Filter "Name='ConnectCoreNetwork.exe'" | Where-Object {$_.ExecutablePath -eq $helperPath});if(!$remaining.Count){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $deadline)
 if($remaining.Count){throw 'Owned helper remained after disconnect'}
 ReceiveCapture (Join-Path $out 'linux-underlay.pcap')
 python "$PSScriptRoot/verify-vm-capture.py" (Join-Path $out 'linux-underlay.pcap') | Set-Content (Join-Path $out 'linux-capture-verification.json');if($LASTEXITCODE){throw 'Linux underlay contained plaintext'}
 $passed=$true
}finally{
 if($client){$client.Status() | Set-Content (Join-Path $out 'final-core-status.log')}
 Get-NetAdapterStatistics -Name 'ccvpn-*' -ErrorAction SilentlyContinue | Select-Object Name,SentBytes,ReceivedBytes,SentUnicastPackets,ReceivedUnicastPackets,OutboundDiscardedPackets,ReceivedDiscardedPackets | ConvertTo-Json | Set-Content (Join-Path $out 'tun-statistics.json')
 netsh wfp show netevents file=$(Join-Path $out 'wfp-events.xml') | Out-Null
 netsh wfp show filters file=$(Join-Path $out 'wfp-filters.xml') | Out-Null
 Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | ConvertTo-Json | Set-Content (Join-Path $out 'final-routes.json')
 Get-NetIPAddress | Select-Object IPAddress,InterfaceIndex,AddressState | ConvertTo-Json | Set-Content (Join-Path $out 'final-addresses.json')
 if(!$passed -and $serial){try{$guestWriter.WriteLine('diagnostics');AwaitGuest '^LAB_DIAGNOSTICS_END$' 20;ReceiveCapture (Join-Path $out 'linux-underlay.pcap')}catch{Write-Warning 'Guest diagnostic capture unavailable'}}
 if($client -and !$client.Process.HasExited){try{$client.Send(5)}catch{};if(!$client.Process.WaitForExit(10000)){$client.Process.Kill();$client.Process.WaitForExit()}}
 if($client){$client.Errors.GetAwaiter().GetResult() | Set-Content (Join-Path $out 'network-helper.log')}
 Start-Sleep -Milliseconds 600
 if(!(RecoverWithDeadline)){
  $passed=$false
  Get-CimInstance Win32_Process -Filter "Name='ConnectCoreNetwork.exe'" | Where-Object {$_.ExecutablePath -eq (Join-Path $dist 'ConnectCoreNetwork.exe')} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
  Start-Sleep -Seconds 1
  [FailedCIGuard]::RemoveOwnDenyForEvidence()
  'CI_ONLY_FORENSIC_GUARD_REMOVAL_NETWORK_TEST_FAILED' | Set-Content (Join-Path $out 'recovery-failed.log')
 }
 if($capture){pktmon stop | Out-Null;pktmon etl2pcap (Join-Path $out 'physical.etl') --out (Join-Path $out 'physical.pcapng') | Out-Null}
 if($vm -and !$vm.HasExited){$vm.Kill();$vm.WaitForExit()}
 $guestLines | Set-Content (Join-Path $out 'linux-console.log')
 if($qemuErrors){$qemuErrors.GetAwaiter().GetResult() | Set-Content (Join-Path $out 'qemu-errors.log')}
 if($serial){$serial.Dispose()};if($listener){$listener.Stop()}
 Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex | ConvertTo-Json | Set-Content (Join-Path $out 'after-adapters.json')
}
if(!$passed){throw 'System VPN validation did not complete; no artifact may be promoted'}
if($passed){
 python "$PSScriptRoot/verify-desktop-physical.py" (Join-Path $out 'physical.pcapng') | Set-Content (Join-Path $out 'physical-capture-verification.json')
 if($LASTEXITCODE){throw 'Physical NIC contained plaintext test payload / DNS'}
 Write-Output 'REAL_SYSTEM_VPN_CROSS_KERNEL_AND_NIC_CAPTURE_CHECKS_PASSED'
}
