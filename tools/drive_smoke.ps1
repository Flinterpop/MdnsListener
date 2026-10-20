# Smoke driver for MDNS Listener: launches its own instance, feeds a known
# number of packets over loopback with feed_mdns.py, reads the packet count
# from the status line, checks no dialog opened, captures a PNG, and closes
# only the instance it started. Posted messages only; no real input.
param(
    [string]$Exe = "$PSScriptRoot\..\build\Release\MdnsListener.exe",
    [int]$Count = 50,
    [string]$Png = "$PSScriptRoot\..\build\claude-scratch\smoke.png"
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class W {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    public struct RECT { public int L, T, R, B; }
    public static IntPtr[] TopLevel(uint pid, string cls) {
        var list = new System.Collections.Generic.List<IntPtr>();
        EnumWindows((h, l) => {
            uint p; GetWindowThreadProcessId(h, out p);
            var sb = new StringBuilder(64); GetClassNameW(h, sb, 64);
            if (p == pid && sb.ToString() == cls && IsWindowVisible(h)) list.Add(h);
            return true;
        }, IntPtr.Zero);
        return list.ToArray();
    }
    public static string Text(IntPtr h) {
        var sb = new StringBuilder(1024);
        SendMessageW(h, 0x000D, (IntPtr)1024, sb);
        return sb.ToString();
    }
}
'@
[W]::SetProcessDPIAware() | Out-Null
Add-Type -AssemblyName System.Drawing

$py = 'C:\Python314\python.exe'
if (-not (Test-Path $py)) { $py = 'C:\Program Files\Python314\python.exe' }
if (-not (Test-Path $py)) { throw "No Python at C:\Python314 or C:\Program Files\Python314" }

$proc = Start-Process -FilePath (Resolve-Path $Exe) -PassThru
try {
    $wnd = [IntPtr]::Zero
    for ($i = 0; $i -lt 50 -and $wnd -eq [IntPtr]::Zero; $i++) {
        Start-Sleep -Milliseconds 100
        $found = [W]::TopLevel([uint32]$proc.Id, 'MdnsListener.Main')
        if ($found.Count -gt 0) { $wnd = $found[0] }
    }
    if ($wnd -eq [IntPtr]::Zero) { throw 'main window never appeared' }
    $status = [W]::GetDlgItem($wnd, 106)
    Start-Sleep -Milliseconds 800
    $before = [W]::Text($status)
    Write-Output "status before: $before"

    & $py -u "$PSScriptRoot\feed_mdns.py" --count $Count --malformed
    Start-Sleep -Milliseconds 1000
    $after = [W]::Text($status)
    Write-Output "status after:  $after"

    $nb = [int]([regex]::Match($before, '(\d+) packets').Groups[1].Value)
    $na = [int]([regex]::Match($after, '(\d+) packets').Groups[1].Value)
    $expected = 3 * $Count
    Write-Output ("delta {0} packets, expected at least {1} (LAN traffic adds to it)" -f ($na - $nb), $expected)

    $dialogs = [W]::TopLevel([uint32]$proc.Id, '#32770').Count
    Write-Output "dialogs open: $dialogs"

    function Capture([string]$path) {
        $r = New-Object W+RECT
        [W]::GetWindowRect($wnd, [ref]$r) | Out-Null
        $bmp = New-Object System.Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
        $gfx = [System.Drawing.Graphics]::FromImage($bmp)
        $dc = $gfx.GetHdc()
        [W]::PrintWindow($wnd, $dc, 2) | Out-Null
        $gfx.ReleaseHdc($dc)
        New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
        $bmp.Save($path)
        $gfx.Dispose(); $bmp.Dispose()
        Write-Output "captured $path"
    }
    function Key([int]$id, [int]$vk, [int]$times = 1) {
        $h = [W]::GetDlgItem($wnd, $id)
        for ($k = 0; $k -lt $times; $k++) {
            [W]::PostMessageW($h, 0x0100, [IntPtr]$vk, [IntPtr]::Zero) | Out-Null
            [W]::PostMessageW($h, 0x0101, [IntPtr]$vk, [IntPtr]0xC0000001) | Out-Null
            Start-Sleep -Milliseconds 60
        }
    }
    Capture $Png
    # The feeder's last round is query, response, malformed: End then Up
    # selects the response. Then walk the decode tree down to a record.
    Key 107 0x23; Key 107 0x26
    Start-Sleep -Milliseconds 300
    Key 109 0x24; Key 109 0x28 12
    Start-Sleep -Milliseconds 300
    Capture ($Png -replace '\.png$', '-decode.png')
    # Sequence tab: Right on the tab control switches tabs and notifies.
    Key 111 0x27
    Start-Sleep -Milliseconds 400
    Capture ($Png -replace '\.png$', '-sequence.png')
    Key 111 0x25
    # Select the first conversation, which filters the log to that host.
    Key 108 0x24
    Start-Sleep -Milliseconds 300
    Capture ($Png -replace '\.png$', '-filter.png')
    # Pause: the packet count must stand still while the held count grows,
    # and resume must add exactly what was held.
    $pauseBtn = [W]::GetDlgItem($wnd, 100)
    [W]::PostMessageW($pauseBtn, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null   # BM_CLICK
    Start-Sleep -Milliseconds 400
    $p0 = [W]::Text($status)
    & $py -u "$PSScriptRoot\feed_mdns.py" --count $Count --malformed
    Start-Sleep -Milliseconds 1000
    $p1 = [W]::Text($status)
    Capture ($Png -replace '\.png$', '-paused.png')
    $pauseText = [W]::Text($pauseBtn)
    [W]::PostMessageW($pauseBtn, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 600
    $p2 = [W]::Text($status)
    Write-Output "paused start:  $p0"
    Write-Output "paused end:    $p1   (button reads '$pauseText')"
    Write-Output "resumed:       $p2"
    $c0 = [int]([regex]::Match($p0, '(\d+) packets').Groups[1].Value)
    $c1 = [int]([regex]::Match($p1, '(\d+) packets').Groups[1].Value)
    $h1 = [int]([regex]::Match($p1, '(\d+) held').Groups[1].Value)
    $c2 = [int]([regex]::Match($p2, '(\d+) packets').Groups[1].Value)
    $pauseOk = ($c1 -eq $c0) -and ($h1 -ge 3 * $Count) -and ($c2 -ge $c1 + $h1) -and ($p2 -notmatch 'PAUSED')
    Write-Output ("pause: count frozen {0}, held {1} (sent {2}), after resume +{3}: {4}" -f
        ($c1 -eq $c0), $h1, (3 * $Count), ($c2 - $c1), $(if ($pauseOk) { 'PASS' } else { 'FAIL' }))

    $dialogs = [W]::TopLevel([uint32]$proc.Id, '#32770').Count
    Write-Output "dialogs open after driving: $dialogs"
    if (($na - $nb) -lt $expected -or $dialogs -ne 0 -or -not $pauseOk) { $code = 1 } else { $code = 0 }
}
finally {
    if (-not $proc.HasExited) {
        if ($wnd -ne [IntPtr]::Zero) { [W]::PostMessageW($wnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null }
        $proc.WaitForExit(5000) | Out-Null
    }
    Write-Output "exited: $($proc.HasExited)"
}
exit $code
