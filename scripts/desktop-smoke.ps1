param([string]$Directory = 'dist')
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DesktopSmoke {
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
}
'@
$exe = (Resolve-Path "$Directory/ConnectCore.exe").Path
$app = Start-Process $exe -PassThru -WindowStyle Hidden
try {
 $deadline = [DateTime]::UtcNow.AddSeconds(15)
 do { Start-Sleep -Milliseconds 100; $app.Refresh() } while ($app.MainWindowHandle -eq 0 -and !$app.HasExited -and [DateTime]::UtcNow -lt $deadline)
 if ($app.HasExited -or $app.MainWindowHandle -eq 0) { throw 'Native window did not open' }
 $worker = @(Get-CimInstance Win32_Process -Filter "Name='connect-desktop-core.exe'" | Where-Object ParentProcessId -eq $app.Id)
 if ($worker.Count -ne 1) { throw 'Expected exactly one Core worker' }
 $scale = [DesktopSmoke]::GetDpiForWindow($app.MainWindowHandle) / 96.0
 # Exercise theme toggle twice through its real native hit area.
 $click = ([int](40*$scale) -shl 16) -bor [int](430*$scale)
 [void][DesktopSmoke]::PostMessage($app.MainWindowHandle,0x202,[IntPtr]::Zero,[IntPtr]$click)
 [void][DesktopSmoke]::PostMessage($app.MainWindowHandle,0x202,[IntPtr]::Zero,[IntPtr]$click)
 [void][DesktopSmoke]::PostMessage($app.MainWindowHandle,0x10,[IntPtr]::Zero,[IntPtr]::Zero)
 if (!$app.WaitForExit(10000)) { throw 'UI shutdown hung' }
 if (Get-Process -Id $worker[0].ProcessId -ErrorAction SilentlyContinue) { throw 'Core worker remained after UI exit' }
 Write-Output 'Native launch, theme messages and graceful worker shutdown passed'
} finally { if (!$app.HasExited) { Stop-Process -Id $app.Id } }
