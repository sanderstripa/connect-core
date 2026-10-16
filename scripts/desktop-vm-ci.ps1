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
using System.Runtime.InteropServices;
public static class NativeConnectWindow {
 public delegate bool EnumCallback(IntPtr h,IntPtr p);
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumCallback callback,IntPtr p);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h,StringBuilder name,int n);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h,uint message,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
 public static IntPtr Find(uint target){IntPtr result=IntPtr.Zero;EnumWindows((h,p)=>{uint pid;GetWindowThreadProcessId(h,out pid);var name=new StringBuilder(256);GetClassName(h,name,256);if(pid==target&&name.ToString()=="ConnectCoreLabWindow"){result=h;return false;}return true;},IntPtr.Zero);return result;}
}
public sealed class CorePipe {
 public Process Process;
 public volatile uint State,Code,Mode,Helper;
 public ulong TX,RX,Elapsed,DNS;
 public bool Ended;
 public Task<string> Errors;
 private readonly object gate=new object();
 private Stream input;
 public CorePipe(string exe,string appData) {
  Directory.CreateDirectory(appData);
  var info=new ProcessStartInfo(exe);info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardInput=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;info.ArgumentList.Add("--ipc");info.Environment["LOCALAPPDATA"]=appData;
  Process=Process.Start(info);input=Process.StandardInput.BaseStream;
  Task.Run(()=>{var output=Process.StandardOutput.BaseStream;try{while(true){byte[] h=Read(output,8);if(h[0]!=67||h[1]!=67||h[2]!=2||h[3]!=128||BitConverter.ToUInt32(h,4)!=176)throw new IOException("Invalid typed status");byte[] b=Read(output,176);lock(gate){Code=BitConverter.ToUInt32(b,4);TX=BitConverter.ToUInt64(b,8);RX=BitConverter.ToUInt64(b,16);Elapsed=BitConverter.ToUInt64(b,24);Mode=BitConverter.ToUInt32(b,32);Helper=BitConverter.ToUInt32(b,164);DNS=BitConverter.ToUInt64(b,168);State=BitConverter.ToUInt32(b,0);}}}catch{Ended=true;}});
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
 if(!$recovery.WaitForExit(15000)){$recovery.Kill();$recovery.WaitForExit();Add-Content (Join-Path $out 'recovery-attempts.log') 'timeout=true';return $false}
 Add-Content (Join-Path $out 'recovery-attempts.log') ('exit_code='+$recovery.ExitCode)
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
 $guestWriter.WriteLine('pause-captures');AwaitGuest '^LAB_CAPTURES_PAUSED$'
 # Inventory only current NICs, BEFORE our Wintun is created; capture never
 # includes the plaintext inner tunnel adapter or generic stack components.
 $components=@();$list=pktmon list --include-hidden;$list | Set-Content (Join-Path $out 'physical-components.log')
 foreach($line in $list){if($line -match '^\s*([0-9]+)\s+(.+)$'){$components+=[int]$Matches[1]}}
 if(!$components.Count){throw 'No physical capture components'}
 Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex | ConvertTo-Json | Set-Content (Join-Path $out 'before-adapters.json')
 $cfg=Get-Content (Join-Path $boot 'lab/ip-client.json') -Raw | ConvertFrom-Json
 foreach($field in 'ca','cert','key'){$cfg.trust.$field=Join-Path $boot ('lab/'+[IO.Path]::GetFileName($cfg.trust.$field))}
 $cfg.destinations=@('0.0.0.0/0');$cfg | Add-Member -NotePropertyName network -NotePropertyValue ([pscustomobject]@{mode='system-vpn';dns='10.232.0.1'})
 $profile=Join-Path $out 'private-client.json';$cfg | ConvertTo-Json -Depth 10 | Set-Content $profile -Encoding utf8NoBOM
 # Isolate real Windows packet handling from TCG's emulated Linux CPU limit.
 # The server here is explicitly a memory UDP reflector, not a Linux/VPS claim.
 $componentCfg=$cfg | ConvertTo-Json -Depth 10 | ConvertFrom-Json
 $componentCfg.endpoint='127.0.0.1:17446'
 $componentProfile=Join-Path $out 'private-component-client.json';$componentCfg | ConvertTo-Json -Depth 10 | Set-Content $componentProfile -Encoding utf8NoBOM
 $componentBinary=Join-Path $root 'build/native-packet-perf.exe'
 # Both clients use the unchanged 0.2.5 protocol backend here, so a client-only
 # upgrade is checked without asking the user to revisit the VPS first.
 $componentInfo=[Diagnostics.ProcessStartInfo]::new((Join-Path $root 'build/native-packet-perf-025.exe'))
 $componentInfo.UseShellExecute=$false;$componentInfo.CreateNoWindow=$true
 $componentInfo.RedirectStandardInput=$true;$componentInfo.RedirectStandardOutput=$true;$componentInfo.RedirectStandardError=$true
 $componentInfo.Environment['CONNECT_DISPOSABLE_NATIVE_PERF']='1'
 $componentInfo.ArgumentList.Add('server');$componentInfo.ArgumentList.Add((Join-Path $boot 'lab/ip-server.json'))
 $componentServer=[Diagnostics.Process]::Start($componentInfo);$componentErrors=$componentServer.StandardError.ReadToEndAsync()
 try {
  $ready=$componentServer.StandardOutput.ReadLineAsync()
  if(!$ready.Wait(10000) -or $ready.GetAwaiter().GetResult() -ne 'NATIVE_PACKET_REFLECTOR_READY'){throw 'Component reflector unavailable'}
  foreach($entry in @(@{name='candidate';exe=(Join-Path $dist 'connect-desktop-core.exe')},@{name='released-025';exe=(Join-Path $root 'build/native-baseline/connect-desktop-core.exe')})) {
   $comparisonHelper=$null;$comparisonHelperStarted=0
   try {
   $client=[CorePipe]::new($entry.exe,(Join-Path $out 'private-profile'))
   $client.Send(1,$componentProfile);AwaitCore 1 10;$client.Send(2);AwaitCore 3
   $componentServer.Refresh();$client.Process.Refresh();$helper=[Diagnostics.Process]::GetProcessById($client.Helper);$helper.Refresh()
   $comparisonHelper=$helper;$comparisonHelperStarted=$helper.StartTime.ToUniversalTime().Ticks
   $serverCpu=$componentServer.TotalProcessorTime.TotalMilliseconds;$workerCpu=$client.Process.TotalProcessorTime.TotalMilliseconds;$helperCpu=$helper.TotalProcessorTime.TotalMilliseconds
   $clock=[Diagnostics.Stopwatch]::StartNew();$env:CONNECT_DISPOSABLE_NATIVE_PERF='1'
   try {
    & $componentBinary probe | Set-Content (Join-Path $out ($entry.name+'-pre-load.log'));if($LASTEXITCODE){throw 'Component forwarding failed before load'}
    & $componentBinary measure | Set-Content (Join-Path $out ($entry.name+'-component-measurements.json'));if($LASTEXITCODE){throw 'Windows packet component measurement failed'}
    & $componentBinary probe | Set-Content (Join-Path $out ($entry.name+'-post-load.log'));if($LASTEXITCODE){throw 'Data did not recover after component load'}
   } finally {Remove-Item Env:CONNECT_DISPOSABLE_NATIVE_PERF -ErrorAction SilentlyContinue}
   $clock.Stop();$componentServer.Refresh();$client.Process.Refresh();$helper.Refresh()
   @{scope='Windows packet component only, memory reflector, no TCG/Linux/Internet';wall_ms=$clock.Elapsed.TotalMilliseconds;worker_cpu_ms=$client.Process.TotalProcessorTime.TotalMilliseconds-$workerCpu;helper_cpu_ms=$helper.TotalProcessorTime.TotalMilliseconds-$helperCpu;reflector_cpu_ms=$componentServer.TotalProcessorTime.TotalMilliseconds-$serverCpu} | ConvertTo-Json | Set-Content (Join-Path $out ($entry.name+'-component-cpu-measurements.json'))
   $client.Send(3);AwaitCore 1 10;$client.Send(5);if(!$client.Process.WaitForExit(10000)){throw 'Component worker shutdown hung'}
   $client.Errors.GetAwaiter().GetResult() | Set-Content (Join-Path $out ($entry.name+'-component-stage-measurements.log'))
   } catch {
    if($entry.name -ne 'released-025'){throw}
    # The immutable old release is a comparison, not a gate that can prevent a
    # fixed candidate from passing a newly added overload regression scenario.
    # Preserve its failure; never convert it into a successful speed sample.
    @{scope='released 0.2.5 comparison failed under new UDP overload';status=$client.Status();measurement_valid=$false} | ConvertTo-Json | Set-Content (Join-Path $out 'released-025-component-failure-measurements.json')
    if(!$client.Process.HasExited){$client.Process.Kill();$client.Process.WaitForExit()}
    $client.Errors.GetAwaiter().GetResult() | Set-Content (Join-Path $out 'released-025-component-stage-measurements.log')
    # Failed Core status can reset Helper to zero while its guarded helper is
    # still alive. Retain the exact pre-load process, never the mutable status.
    if($comparisonHelper){
     $legacyHelper=$comparisonHelper
     if($legacyHelper -and !$legacyHelper.HasExited){
      $expectedLegacyHelper=(Resolve-Path (Join-Path $root 'build/native-baseline/ConnectCoreNetwork.exe')).Path
      if($legacyHelper.MainModule.FileName -ne $expectedLegacyHelper -or $legacyHelper.StartTime.ToUniversalTime().Ticks -ne $comparisonHelperStarted){throw 'Legacy helper identity changed'}
      $legacyHelper.Kill();$legacyHelper.WaitForExit()
     }
    }
    if(!(RecoverWithDeadline)){throw 'Recovery after legacy comparison failed'}
    Write-Warning 'Released 0.2.5 failed the additional component overload comparison; failure evidence saved.'
   }
  }
 } finally {
  if(!$componentServer.HasExited){$componentServer.StandardInput.WriteLine('stop');$componentServer.StandardInput.Close();if(!$componentServer.WaitForExit(10000)){$componentServer.Kill();$componentServer.WaitForExit()}}
  $componentErrors.GetAwaiter().GetResult() | Set-Content (Join-Path $out 'component-reflector.log')
 }
 $client=[CorePipe]::new((Join-Path $dist 'connect-desktop-core.exe'),(Join-Path $out 'private-profile'))
 netsh wfp set options netevents=on | Out-Null
 $guestWriter.WriteLine('latency-80');AwaitGuest '^LAB_LATENCY_80$'
 $client.Send(1,$profile);AwaitCore 1 10;$client.Send(2);AwaitCore 3
 if($client.Mode -ne 1){throw 'System Wintun mode not active'}
 Write-Output 'REAL_WINDOWS_WINTUN_SYSTEM_ROUTES_READY'
 # Compare the released Windows binaries and this candidate on the SAME live
 # guest, Wintun, full-system policy and TCP fixture. Pipe-only tests miss this.
 function MeasureNativeDuplex([string]$label) {
  $networkStats=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
  $udpErrors=$networkStats.GetUdpIPv4Statistics().IncomingDatagramsWithErrors
  $tcpRetransmits=$networkStats.GetTcpIPv4Statistics().SegmentsResent
  $helper=[Diagnostics.Process]::GetProcessById($client.Helper)
  $client.Process.Refresh();$helper.Refresh()
  $vm.Refresh();$guestCpu=$vm.TotalProcessorTime.TotalMilliseconds
  $workerCpu=$client.Process.TotalProcessorTime.TotalMilliseconds;$helperCpu=$helper.TotalProcessorTime.TotalMilliseconds
  $clock=[Diagnostics.Stopwatch]::StartNew()
  python "$PSScriptRoot/ip-lab-services.py" throughput | Set-Content (Join-Path $out ($label+'-throughput-measurements.json'))
  if($LASTEXITCODE){throw ('Native duplex throughput failed: '+$label)}
  $clock.Stop();$client.Process.Refresh();$helper.Refresh();$vm.Refresh()
  @{scope='disposable Windows Wintun + Linux QEMU, not public VPS; host counters include background traffic';wall_ms=$clock.Elapsed.TotalMilliseconds;worker_cpu_ms=$client.Process.TotalProcessorTime.TotalMilliseconds-$workerCpu;helper_cpu_ms=$helper.TotalProcessorTime.TotalMilliseconds-$helperCpu;guest_qemu_cpu_ms=$vm.TotalProcessorTime.TotalMilliseconds-$guestCpu;host_udp_errors_delta=$networkStats.GetUdpIPv4Statistics().IncomingDatagramsWithErrors-$udpErrors;host_tcp_retransmits_delta=$networkStats.GetTcpIPv4Statistics().SegmentsResent-$tcpRetransmits} | ConvertTo-Json | Set-Content (Join-Path $out ($label+'-cpu-measurements.json'))
 }
 MeasureNativeDuplex 'candidate'
 $client.Send(3);AwaitCore 1 10;$client.Send(5);if(!$client.Process.WaitForExit(10000)){throw 'Candidate shutdown before comparison hung'}
 $client.Errors.GetAwaiter().GetResult() | Set-Content (Join-Path $out 'candidate-stage-measurements.log')
 $client=[CorePipe]::new((Join-Path $root 'build/native-baseline/connect-desktop-core.exe'),(Join-Path $out 'private-profile'))
 AwaitCore 1 10;$client.Send(2);AwaitCore 3
 MeasureNativeDuplex 'released-025'
 $client.Send(3);AwaitCore 1 10;$client.Send(5);if(!$client.Process.WaitForExit(10000)){throw 'Baseline shutdown after comparison hung'}
 $client.Errors.GetAwaiter().GetResult() | Set-Content (Join-Path $out 'released-025-stage-measurements.log')
 $guestWriter.WriteLine('latency-clear');AwaitGuest '^LAB_LATENCY_CLEAR$'
 $guestWriter.WriteLine('resume-captures');AwaitGuest '^LAB_CAPTURES_RESUMED$'
 # Performance traffic has its own counters. Preserve complete captures of
 # every original security scenario, without bulk files exhausting UART export.
 'Performance comparison excluded; complete ordinary TCP/UDP/DNS, failure/recovery and native-window scenarios follow with both captures active.' | Set-Content (Join-Path $out 'capture-scope.log')
 pktmon start --capture --comp $components --pkt-size 0 --file-name (Join-Path $out 'physical.etl') | Out-Null
 if($LASTEXITCODE){throw 'NIC capture failed'};$capture=$true
 Invoke-WebRequest 'https://www.wintun.net/' -TimeoutSec 30 -OutFile (Join-Path $out 'capture-baseline.html')
 $client=[CorePipe]::new((Join-Path $dist 'connect-desktop-core.exe'),(Join-Path $out 'private-profile'))
 AwaitCore 1 10;$client.Send(2);AwaitCore 3
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
 if(!$client.Helper){throw 'Authenticated helper PID unavailable'}
 $ownedHelper=[Diagnostics.Process]::GetProcessById($client.Helper);if($ownedHelper.MainModule.FileName -ne $helperPath){throw 'Authenticated helper image changed'}
 $ownedHelper.Kill();$ownedHelper.WaitForExit();AwaitCore 4 10
 python "$PSScriptRoot/ip-lab-services.py" failure | Set-Content (Join-Path $out 'helper-failure.log');if($LASTEXITCODE){throw 'Helper crash fell back direct'}
 python "$PSScriptRoot/vm-negative-probes.py" | Set-Content (Join-Path $out 'helper-crash-probes.json');if($LASTEXITCODE){throw 'Helper crash exposed direct network'}
 $client.Send(8);AwaitCore 1 15;$client.Send(2);AwaitCore 3
 python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'helper-recovery-measurements.json');if($LASTEXITCODE){throw 'Client-command recovery failed'}
 Write-Output 'HELPER_CRASH_AND_CLIENT_IPC_RECOVERY_PASSED'
 $client.Send(3);AwaitCore 1 10;$client.Send(5);if(!$client.Process.WaitForExit(10000)){throw 'Worker shutdown hung'}
 # Exercise the actual native window's worker pipes and Connect click. Direct
 # worker tests cannot detect stderr being mixed into the binary UI channel.
 $guiInfo=[Diagnostics.ProcessStartInfo]::new((Join-Path $dist 'ConnectCore.exe'));$guiInfo.UseShellExecute=$false;$guiInfo.CreateNoWindow=$true;$guiInfo.Environment['LOCALAPPDATA']=Join-Path $out 'private-profile'
 $gui=[Diagnostics.Process]::Start($guiInfo)
 try {
  $deadline=[DateTime]::UtcNow.AddSeconds(15);$hwnd=[IntPtr]::Zero
  do {Start-Sleep -Milliseconds 100;$hwnd=[NativeConnectWindow]::Find($gui.Id)}while($hwnd -eq [IntPtr]::Zero -and !$gui.HasExited -and [DateTime]::UtcNow -lt $deadline)
  if($hwnd -eq [IntPtr]::Zero){throw 'Native connection window unavailable'}
  Start-Sleep -Seconds 2
  $scale=[NativeConnectWindow]::GetDpiForWindow($hwnd)/96.0;$click=([int](257*$scale) -shl 16) -bor [int](259*$scale)
  [void][NativeConnectWindow]::PostMessage($hwnd,0x202,[IntPtr]::Zero,[IntPtr]$click)
  $deadline=[DateTime]::UtcNow.AddSeconds(40)
  do {Start-Sleep -Milliseconds 250;$adapter=@(Get-NetAdapter -Name 'ccvpn-*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')}while(!$adapter.Count -and !$gui.HasExited -and [DateTime]::UtcNow -lt $deadline)
  if(!$adapter.Count){throw 'Native Connect click did not create its tunnel'}
  Start-Sleep -Seconds 4
  python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'native-window-measurements.json')
  if($LASTEXITCODE){throw 'Actual native window failed TCP/UDP/DNS connection'}
  $worker=@(Get-CimInstance Win32_Process -Filter "Name='connect-desktop-core.exe'" | Where-Object ParentProcessId -eq $gui.Id)
  if($worker.Count -ne 1){throw 'Native window lost its worker to diagnostic output'}
  [void][NativeConnectWindow]::PostMessage($hwnd,0x202,[IntPtr]::Zero,[IntPtr]$click)
  Start-Sleep -Seconds 2
  [void][NativeConnectWindow]::PostMessage($hwnd,0x10,[IntPtr]::Zero,[IntPtr]::Zero)
  if(!$gui.WaitForExit(10000)){throw 'Native window shutdown hung'}
  $diagnostics=Get-Content (Join-Path $out 'private-profile/ConnectCoreLab/diagnostics.log') -Raw
  if($diagnostics -notmatch '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z' -or $diagnostics -notmatch 'CONNECT Wintun counters'){throw 'Persistent native diagnostics missing'}
  if($diagnostics -match 'PRIVATE KEY|connect://enroll'){throw 'Native diagnostics exposed private material'}
  Write-Output 'NATIVE_WINDOW_CONNECT_TCP_UDP_DNS_STDERR_ISOLATION_PASSED'
 } finally {if(!$gui.HasExited){$gui.Kill();$gui.WaitForExit()}}
 $deadline=[DateTime]::UtcNow.AddSeconds(5);do{$remaining=@(Get-CimInstance Win32_Process -Filter "Name='ConnectCoreNetwork.exe'" | Where-Object {$_.ExecutablePath -eq $helperPath});if(!$remaining.Count){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $deadline)
 if($remaining.Count){throw 'Owned helper remained after disconnect'}
 ReceiveCapture (Join-Path $out 'linux-underlay.pcap')
 python "$PSScriptRoot/verify-vm-capture.py" (Join-Path $out 'linux-underlay.pcap') | Set-Content (Join-Path $out 'linux-capture-verification.json');if($LASTEXITCODE){throw 'Linux underlay contained plaintext'}
 # Regression: a non-loopback server must NOT acquire an IP-wide physical
 # /32 exception. The fixture uses TEST-NET-2, never a user's VPS. A previous
 # client created the host route here and fails this assertion. No server is
 # expected at this address; only the encrypted UDP socket may use underlay.
 $routeCfg=$cfg | ConvertTo-Json -Depth 10 | ConvertFrom-Json
 $routeCfg.endpoint='198.51.100.2:17444'
 $routeProfile=Join-Path $out 'private-route-client.json'
 $routeCfg | ConvertTo-Json -Depth 10 | Set-Content $routeProfile -Encoding utf8NoBOM
 $client=[CorePipe]::new((Join-Path $dist 'connect-desktop-core.exe'),(Join-Path $out 'private-route-profile'))
 $client.Send(1,$routeProfile);AwaitCore 1 10;$client.Send(2)
 $deadline=[DateTime]::UtcNow.AddSeconds(15)
 do {
  $route=@(Find-NetRoute -RemoteIPAddress '198.51.100.2' | Where-Object {$_.DestinationPrefix})
  $tun=@(Get-NetAdapter -Name ('ccvpn-'+$client.Process.Id) -ErrorAction SilentlyContinue)
  if($tun.Count -eq 1 -and $route.Count -eq 1 -and $route[0].InterfaceIndex -eq $tun[0].ifIndex){break}
  Start-Sleep -Milliseconds 100
 }while([DateTime]::UtcNow -lt $deadline -and !$client.Process.HasExited)
 if($tun.Count -ne 1 -or $route.Count -ne 1 -or $route[0].InterfaceIndex -ne $tun[0].ifIndex){throw 'Same-IP panel destination bypasses the tunnel'}
 if(@(Get-NetRoute -DestinationPrefix '198.51.100.2/32' -ErrorAction SilentlyContinue).Count){throw 'IP-wide endpoint exclusion reappeared'}
 $route | Select-Object DestinationPrefix,InterfaceIndex,NextHop | ConvertTo-Json | Set-Content (Join-Path $out 'same-ip-panel-route.json')
 $client.Process.Kill();$client.Process.WaitForExit();Start-Sleep -Seconds 2
 python "$PSScriptRoot/vm-negative-probes.py" 198.51.100.2 | Set-Content (Join-Path $out 'same-ip-route-crash-probes.json');if($LASTEXITCODE){throw 'Socket-bound transport crash exposed direct network'}
 if(!(RecoverWithDeadline)){throw 'Socket-bound transport recovery failed'}
 Write-Output 'SAME_SERVER_IP_APPLICATION_ROUTE_AND_FAIL_CLOSED_PASSED'
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
 if($client){$safeHelperLog=$client.Errors.GetAwaiter().GetResult();$safeHelperLog | Set-Content (Join-Path $out 'network-helper.log');Write-Output $safeHelperLog}
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
 Clear-DnsClientCache
 Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex | ConvertTo-Json | Set-Content (Join-Path $out 'after-adapters.json')
}
if(!$passed){throw 'System VPN validation did not complete; no artifact may be promoted'}
if($passed){
 python "$PSScriptRoot/verify-desktop-physical.py" (Join-Path $out 'physical.pcapng') | Set-Content (Join-Path $out 'physical-capture-verification.json')
 if($LASTEXITCODE){throw 'Physical NIC contained plaintext test payload / DNS'}
 Write-Output 'REAL_SYSTEM_VPN_CROSS_KERNEL_AND_NIC_CAPTURE_CHECKS_PASSED'
}
