param([string]$Directory = 'dist')
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DesktopSmoke {
 public delegate bool EnumCallback(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumCallback callback, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
 public static IntPtr FindWindow(uint target) { IntPtr found=IntPtr.Zero; EnumWindows((h,l)=>{ uint pid; GetWindowThreadProcessId(h,out pid); if(pid==target){found=h;return false;} return true;},IntPtr.Zero); return found; }
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
}
'@
$exe = (Resolve-Path "$Directory/ConnectCore.exe").Path
$app = Start-Process $exe -PassThru -WindowStyle Hidden
try {
 $deadline = [DateTime]::UtcNow.AddSeconds(15)
 do { Start-Sleep -Milliseconds 100; $app.Refresh(); $hwnd = [DesktopSmoke]::FindWindow($app.Id) } while ($hwnd -eq [IntPtr]::Zero -and !$app.HasExited -and [DateTime]::UtcNow -lt $deadline)
 if ($app.HasExited -or $hwnd -eq [IntPtr]::Zero) { throw 'Native window did not open' }
 $worker = @(Get-CimInstance Win32_Process -Filter "Name='connect-desktop-core.exe'" | Where-Object ParentProcessId -eq $app.Id)
 if ($worker.Count -ne 1) { throw 'Expected exactly one Core worker' }
 $scale = [DesktopSmoke]::GetDpiForWindow($hwnd) / 96.0
 # Exercise theme toggle twice through its real native hit area.
 $click = ([int](40*$scale) -shl 16) -bor [int](430*$scale)
 [void][DesktopSmoke]::PostMessage($hwnd,0x202,[IntPtr]::Zero,[IntPtr]$click)
 [void][DesktopSmoke]::PostMessage($hwnd,0x202,[IntPtr]::Zero,[IntPtr]$click)
 [void][DesktopSmoke]::PostMessage($hwnd,0x10,[IntPtr]::Zero,[IntPtr]::Zero)
 if (!$app.WaitForExit(10000)) { throw 'UI shutdown hung' }
 if (Get-Process -Id $worker[0].ProcessId -ErrorAction SilentlyContinue) { throw 'Core worker remained after UI exit' }
 Write-Output 'Native launch, theme messages and graceful worker shutdown passed'
} finally { if (!$app.HasExited) { Stop-Process -Id $app.Id } }
