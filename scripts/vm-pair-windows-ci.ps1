$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'VM-pair harness runs only in a disposable Windows CI VM'}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$boot=Join-Path $root 'vm-boot';$out=Join-Path $root 'vm-pair-artifacts';$bin=Join-Path $root 'bin'
New-Item -ItemType Directory -Force $out,$bin | Out-Null
$installer=Join-Path $out 'qemu-setup.exe'
Invoke-WebRequest 'https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe' -OutFile $installer -TimeoutSec 120
$expected='5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543'
if((Get-FileHash -LiteralPath $installer -Algorithm SHA512).Hash.ToLower() -ne $expected){throw 'Pinned QEMU publisher hash mismatch'}
$install=Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
if($install.ExitCode -ne 0){throw 'QEMU installation failed'}
$qemu=Join-Path ${env:ProgramFiles} 'qemu/qemu-system-x86_64.exe'
foreach($name in 'vmlinuz','rootfs.cpio.gz'){
 $entry=Get-Content (Join-Path $boot 'boot-sha256.txt') | Where-Object { $_.EndsWith('/'+$name) }
 if(-not $entry -or (Get-FileHash (Join-Path $boot $name) -Algorithm SHA256).Hash.ToLower() -ne $entry.Split(' ')[0]){throw 'Guest boot artifact hash mismatch'}
}
# Fetch only the official pinned/signed Wintun, before network guarding begins.
$archive=Join-Path $out 'wintun.zip'
Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive -TimeoutSec 60
if((Get-FileHash $archive -Algorithm SHA256).Hash -ne '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'){throw 'Wintun archive hash mismatch'}
Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $out 'vendor')
$dll=Join-Path $out 'vendor/wintun/bin/amd64/wintun.dll'
$signature=Get-AuthenticodeSignature $dll
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=WireGuard LLC'){throw 'Wintun publisher signature rejected'}
Copy-Item -LiteralPath $dll -Destination (Join-Path $bin 'wintun.dll')
go build -o bin/connect-core.exe ./cmd/connect-core
if($LASTEXITCODE -ne 0){throw 'Windows core build failed'}
$rogue=Join-Path $boot 'rogue'
& (Join-Path $bin 'connect-core.exe') init-lab $rogue | Out-Null
if($LASTEXITCODE -ne 0){throw 'Negative identity fixture generation failed'}

function Start-LabProcess([string]$file,[string[]]$arguments){
 $info=[Diagnostics.ProcessStartInfo]::new($file);$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.RedirectStandardInput=$true
 foreach($argument in $arguments){$info.ArgumentList.Add($argument)}
 $p=[Diagnostics.Process]::Start($info)
 $p.StandardInput.NewLine="`n"
 return [pscustomobject]@{process=$p;reader=$p.StandardOutput;writer=$p.StandardInput;pending=$p.StandardOutput.ReadLineAsync();lines=[Collections.Generic.List[string]]::new();history=[Collections.Generic.List[string]]::new();error=$p.StandardError.ReadToEndAsync()}
}
function Pump($record){
 while($record.pending -and $record.pending.IsCompleted){
  $line=$record.pending.GetAwaiter().GetResult()
  if($null -eq $line){$record.pending=$null;break}
  $record.lines.Add($line);$record.history.Add($line);$record.pending=$record.reader.ReadLineAsync()
 }
}
function Await-Line($record,[string]$pattern,[int]$seconds=60){
 $deadline=[DateTime]::UtcNow.AddSeconds($seconds)
 while([DateTime]::UtcNow -lt $deadline){Pump $record;if(@($record.lines | Where-Object {$_ -match $pattern}).Count){return};if($record.process.HasExited){throw "Lab process exited before $pattern"};Start-Sleep -Milliseconds 20}
 throw ("Timed out waiting for $pattern; last output: " + ($record.history | Select-Object -Last 12 | Out-String))
}
function Clear-Lines($record){Pump $record;$record.lines.Clear()}
$vm=$null;$client=$null;$badProcess=$null;$serialListener=$null;$serialPeer=$null;$captureStarted=$false;$journal=Join-Path $out 'network-journal.json';$badPath=Join-Path $out 'bad-client.json'
$env:CONNECT_IP_LAB_VM='1'
$cfg=Get-Content (Join-Path $boot 'lab/ip-client.json') -Raw | ConvertFrom-Json
$cfg.interface='ccipvm'
foreach($field in 'ca','cert','key'){$cfg.trust.$field=Join-Path $boot ('lab/'+[IO.Path]::GetFileName($cfg.trust.$field))}
$profile=Join-Path $out 'client.json';$cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $profile
try{
 # A second, independent Linux kernel; no host bridge/TAP, Hyper-V or physical
 # route changes. Guest default-drop rules and no default route isolate SLIRP;
 # its restrict mode cannot carry UDP replies (see VM-PAIR.md).
 $serialListener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,17445);$serialListener.Start()
 $accept=$serialListener.AcceptTcpClientAsync()
 $vm=Start-LabProcess $qemu @('-machine','q35','-accel','tcg,thread=multi','-smp','2','-m','768','-display','none','-monitor','none','-chardev','socket,id=control,host=127.0.0.1,port=17445','-serial','chardev:control','-no-reboot','-kernel',(Join-Path $boot 'vmlinuz'),'-initrd',(Join-Path $boot 'rootfs.cpio.gz'),'-append','console=ttyS0 rdinit=/init connect_lab_vm=1 panic=1','-netdev','user,id=lab,hostfwd=udp:127.0.0.1:17444-:17444','-device','virtio-net-pci,netdev=lab')
 if(-not $accept.Wait(10000)){throw 'QEMU serial controller did not connect'}
 $serialPeer=$accept.GetAwaiter().GetResult();$serialListener.Stop()
 $vm.reader=[IO.StreamReader]::new($serialPeer.GetStream())
 $vm.writer=[IO.StreamWriter]::new($serialPeer.GetStream(),[Text.UTF8Encoding]::new($false));$vm.writer.AutoFlush=$true;$vm.writer.NewLine="`n"
 $vm.pending=$vm.reader.ReadLineAsync()
 Await-Line $vm '^LAB_SERVER_READY$' 180
 $vm.writer.WriteLine('diagnostics');Await-Line $vm '^LAB_DIAGNOSTICS_END$' 15
 Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'windows-adapters.log')
 $client=Start-LabProcess (Join-Path $bin 'connect-core.exe') @('ip-client-managed',$profile)
 Await-Line $client '"state":"ready"' 30
 & "$PSScriptRoot/lab-network-windows.ps1" -Action apply -Journal $journal -Config $profile
 # Record Windows packets as an additional artifact; Linux PCAP is analyzed.
 pktmon list | Set-Content (Join-Path $out 'windows-components.log')
 Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'windows-adapters.log')
 pktmon start --capture --comp nics --pkt-size 0 --file-name (Join-Path $out 'windows.etl') | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Windows capture did not start'};$captureStarted=$true
 $startCpu=$client.process.TotalProcessorTime.TotalSeconds;$watch=[Diagnostics.Stopwatch]::StartNew()
 python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'measurements.json')
 if($LASTEXITCODE -ne 0){throw 'Cross-VM HTTP/TCP/UDP/DNS checks failed'}
 python -c "import socket,time; n='probe'+str(time.time_ns())+'.test'; r=socket.getaddrinfo(n,80,socket.AF_INET); assert r and all(x[4][0]=='10.232.0.1' for x in r); print('Windows system resolver through Linux DNS passed')"
 if($LASTEXITCODE -ne 0){throw 'System DNS failed'}
 # Wrong name must fail before creating another interface; no weakened trust.
 $bad=($cfg | ConvertTo-Json -Depth 10 | ConvertFrom-Json);$bad.interface='ccipbad';$bad.trust.server_name='invalid.test'
 $badPath=Join-Path $out 'bad-client.json';$bad | ConvertTo-Json -Depth 10 | Set-Content $badPath
 $badProcess=Start-LabProcess (Join-Path $bin 'connect-core.exe') @('ip-client-managed',$badPath)
 if(-not $badProcess.process.WaitForExit(15000) -or $badProcess.process.ExitCode -eq 0){throw 'Bad certificate/name was accepted'}
 if(Get-NetAdapter -Name 'ccipbad' -ErrorAction SilentlyContinue){throw 'Bad authentication created an interface'}
 # A real client leaf/key issued by another disposable CA must also be denied.
 $bad.trust.server_name=$cfg.trust.server_name
 $bad.trust.cert=Join-Path $rogue 'client.pem';$bad.trust.key=Join-Path $rogue 'client.key'
 $bad | ConvertTo-Json -Depth 10 | Set-Content $badPath
 $badProcess=Start-LabProcess (Join-Path $bin 'connect-core.exe') @('ip-client-managed',$badPath)
 if(-not $badProcess.process.WaitForExit(15000) -or $badProcess.process.ExitCode -eq 0){throw 'Foreign client certificate was accepted'}
 if(Get-NetAdapter -Name 'ccipbad' -ErrorAction SilentlyContinue){throw 'Foreign identity created an interface'}
 python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [s.sendto(b'CONNECT-invalid-'+bytes([i]),('127.0.0.1',17444)) for i in range(100)]; s.close()"
 if($LASTEXITCODE -ne 0){throw 'Malformed underlay probe failed'}
 # Authenticated client retains TUN/routes/firewall during loss and reconnect.
 Clear-Lines $vm;Clear-Lines $client;$vm.writer.WriteLine('stop-server')
 Await-Line $vm '^LAB_SERVER_STOPPED$'
 python "$PSScriptRoot/ip-lab-services.py" failure
 if($LASTEXITCODE -ne 0){throw 'Endpoint failure leaked'}
 Await-Line $client '"state":"reconnecting"' 35
 if(-not (Get-NetAdapter -Name 'ccipvm' -ErrorAction SilentlyContinue)){throw 'Reconnect removed the protected interface'}
 Clear-Lines $vm;Clear-Lines $client;$vm.writer.WriteLine('start-server')
 Await-Line $vm '^LAB_SERVER_READY$'
 Await-Line $client '"state":"ready"' 35
 python "$PSScriptRoot/ip-lab-services.py" check | Set-Content (Join-Path $out 'recovery-measurements.json')
 if($LASTEXITCODE -ne 0){throw 'Recovery failed'}
 python "$PSScriptRoot/vm-negative-probes.py"
 if($LASTEXITCODE -ne 0){throw 'IPv4/IPv6/DNS guard failed'}
 $client.process.Refresh();$watch.Stop()
 @{cpu_seconds=$client.process.TotalProcessorTime.TotalSeconds-$startCpu;wall_seconds=$watch.Elapsed.TotalSeconds;working_set_bytes=$client.process.WorkingSet64;peak_working_set_bytes=$client.process.PeakWorkingSet64} | ConvertTo-Json | Set-Content (Join-Path $out 'windows-resources.json')
 Clear-Lines $vm;$vm.writer.WriteLine('metrics');Await-Line $vm '^LAB_LINUX_METRICS '
 @($vm.lines | Where-Object {$_ -match '^LAB_LINUX_METRICS '})[-1].Substring(18) | Set-Content (Join-Path $out 'linux-resources.json')
 # Deliberately crash Core: persistent guard must still stop direct fallback.
 $client.process.Kill();$client.process.WaitForExit()
 python "$PSScriptRoot/ip-lab-services.py" failure
 if($LASTEXITCODE -ne 0){throw 'Core crash leaked'}
 python "$PSScriptRoot/vm-negative-probes.py"
 if($LASTEXITCODE -ne 0){throw 'Crash guard failed'}
 Clear-Lines $vm;$vm.writer.WriteLine('capture');Await-Line $vm '^LAB_PCAP_END$' 180
 $begin=$vm.lines.IndexOf('LAB_PCAP_BEGIN');$end=$vm.lines.IndexOf('LAB_PCAP_END')
 [IO.File]::WriteAllBytes((Join-Path $out 'linux-underlay.pcap'),[Convert]::FromBase64String(($vm.lines.GetRange($begin+1,$end-$begin-1) -join '')))
 python "$PSScriptRoot/verify-vm-capture.py" (Join-Path $out 'linux-underlay.pcap') | Set-Content (Join-Path $out 'capture-verification.json')
 if($LASTEXITCODE -ne 0){throw 'Linux underlay capture leak check failed'}
 Write-Output 'WINDOWS_LINUX_VM_PAIR_PASSED'
}finally{
 try{
  if($vm -and -not $vm.process.HasExited -and -not (Test-Path (Join-Path $out 'linux-underlay.pcap'))){
   try{
    Clear-Lines $vm;$vm.writer.WriteLine('diagnostics');Await-Line $vm '^LAB_DIAGNOSTICS_END$' 10
    Clear-Lines $vm;$vm.writer.WriteLine('capture');Await-Line $vm '^LAB_PCAP_END$' 30
    $begin=$vm.lines.IndexOf('LAB_PCAP_BEGIN');$end=$vm.lines.IndexOf('LAB_PCAP_END')
    [IO.File]::WriteAllBytes((Join-Path $out 'linux-underlay.pcap'),[Convert]::FromBase64String(($vm.lines.GetRange($begin+1,$end-$begin-1) -join '')))
   }catch{Write-Warning ('Failure capture unavailable: '+$_.Exception.Message)}
  }
  if($captureStarted){pktmon stop | Out-Null;pktmon etl2pcap (Join-Path $out 'windows.etl') --out (Join-Path $out 'windows.pcapng') | Out-Null}
  if(Test-Path -LiteralPath $journal){
   & "$PSScriptRoot/lab-network-windows.ps1" -Action rollback -Journal $journal
   $rolled=Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
   if($rolled.phase -ne 'rolled-back' -or (Get-NetFirewallRule -Name ($rolled.id+'-*') -ErrorAction SilentlyContinue) -or (Get-DnsClientNrptRule | Where-Object Comment -eq $rolled.id)){throw 'Network rollback left owned rules'}
   Write-Output 'LAB_NETWORK_ROLLBACK_PASSED'
  }
 }finally{
 foreach($record in @($client,$vm,$badProcess)){
  if($record){if(-not $record.process.HasExited){$record.process.Kill();$record.process.WaitForExit()};Pump $record;$name=if($record -eq $vm){'linux-console'}elseif($record -eq $badProcess){'bad-client'}else{'client-events'};$record.history | Set-Content (Join-Path $out ($name+'.log'));$record.error.GetAwaiter().GetResult() | Set-Content (Join-Path $out ($name+'-stderr.log'))}
 }
 if($serialPeer){$serialPeer.Dispose()};if($serialListener){$serialListener.Stop()}
 # Credentials, vendor binaries and boot image are never uploaded as results.
 Remove-Item -LiteralPath $profile,$badPath -ErrorAction SilentlyContinue
 Remove-Item Env:CONNECT_IP_LAB_VM -ErrorAction SilentlyContinue
 }
}
