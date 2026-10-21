# Layout driver for MDNS Listener: the three splitters and a DPI change.
# Launches its own instance with a capture file (so nothing is listening),
# uses posted and sent messages only (no real input), and closes only that.
#
#   1. Each splitter is dragged by posted WM_LBUTTONDOWN / WM_MOUSEMOVE /
#      WM_LBUTTONUP at its gap; the panes either side must move by the drag,
#      and a drag far past the edge must stop at the clamp with both panes
#      still showing.
#   2. WM_DPICHANGED is sent to 96 dpi and back, each with a suggested
#      rectangle (Windows marshals it). Written on a one-monitor machine, so
#      the change is forged, not real: it checks the app's handling (window
#      to the suggested rect, controls and column widths rescaled), not
#      Windows' choice of when to send it.
param(
    [string]$Exe = '',
    [Parameter(Mandatory = $true)][string]$File,
    [string]$Png = ''
)
$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty in a param default under Windows PowerShell 5.1.
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Exe) { $Exe = Join-Path $repo 'build\Release\MdnsListener.exe' }
if (-not $Png) { $Png = Join-Path $repo 'build\claude-scratch\layout.png' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class L {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    public struct RECT { public int L, T, R, B; }
    public struct POINT { public int X, Y; }
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool ScreenToClient(IntPtr h, ref POINT p);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
    static string Cls(IntPtr h) { var sb = new StringBuilder(64); GetClassNameW(h, sb, 64); return sb.ToString(); }
    public static IntPtr[] TopLevel(uint pid, string cls) {
        var list = new System.Collections.Generic.List<IntPtr>();
        EnumWindows((h, l) => {
            uint p; GetWindowThreadProcessId(h, out p);
            if (p == pid && Cls(h) == cls && IsWindowVisible(h)) list.Add(h);
            return true;
        }, IntPtr.Zero);
        return list.ToArray();
    }
    // A child's rectangle in its parent's client coordinates.
    public static RECT ClientRect(IntPtr parent, IntPtr child) {
        RECT r; GetWindowRect(child, out r);
        var a = new POINT { X = r.L, Y = r.T }; var b = new POINT { X = r.R, Y = r.B };
        ScreenToClient(parent, ref a); ScreenToClient(parent, ref b);
        return new RECT { L = a.X, T = a.Y, R = b.X, B = b.Y };
    }
    // WM_DPICHANGED with its suggested RECT. Windows marshals that RECT, so the
    // pointer is into this process (one into the target's arrives as nothing).
    public static void ForgeDpi(IntPtr w, int dpi, RECT s) {
        IntPtr loc = Marshal.AllocHGlobal(16);
        try {
            Marshal.Copy(new int[] { s.L, s.T, s.R, s.B }, 0, loc, 4);
            SendMessageW(w, 0x02E0, (IntPtr)((dpi << 16) | dpi), loc);
        } finally { Marshal.FreeHGlobal(loc); }
    }
}
'@
[L]::SetProcessDPIAware() | Out-Null
Add-Type -AssemblyName System.Drawing
$script:fail = 0
function Verdict([string]$what, [bool]$ok) {
    if (-not $ok) { $script:fail++ }
    Write-Output ("{0}: {1}" -f $what, $(if ($ok) { 'PASS' } else { 'FAIL' }))
}
function Capture($w, [string]$path) {
    $r = New-Object L+RECT
    [L]::GetWindowRect($w, [ref]$r) | Out-Null
    $bmp = New-Object System.Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $dc = $gfx.GetHdc()
    [L]::PrintWindow($w, $dc, 2) | Out-Null
    $gfx.ReleaseHdc($dc)
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    $bmp.Save($path)
    $gfx.Dispose(); $bmp.Dispose()
    Write-Output "captured $path"
}
function Pane($w, [int]$id) { return [L]::ClientRect($w, [L]::GetDlgItem($w, $id)) }
function PointLp([int]$x, [int]$y) { return [IntPtr](($y -shl 16) -bor ($x -band 0xFFFF)) }
# Drags from (x0,y0) to (x1,y1) in client coordinates, with posted messages.
function DragSplit($w, [int]$x0, [int]$y0, [int]$x1, [int]$y1) {
    [L]::PostMessageW($w, 0x0201, [IntPtr]1, (PointLp $x0 $y0)) | Out-Null   # WM_LBUTTONDOWN
    foreach ($k in 1..4) {
        $x = $x0 + [int](($x1 - $x0) * $k / 4); $y = $y0 + [int](($y1 - $y0) * $k / 4)
        [L]::PostMessageW($w, 0x0200, [IntPtr]1, (PointLp $x $y)) | Out-Null  # WM_MOUSEMOVE, MK_LBUTTON
    }
    [L]::PostMessageW($w, 0x0202, [IntPtr]0, (PointLp $x1 $y1)) | Out-Null   # WM_LBUTTONUP
    Start-Sleep -Milliseconds 300
}
function Width($r) { return $r.R - $r.L }
function Height($r) { return $r.B - $r.T }

$File = (Resolve-Path $File).Path
$p = Start-Process -FilePath (Resolve-Path $Exe) -ArgumentList "`"$File`"" -PassThru
$w = [IntPtr]::Zero
for ($i = 0; $i -lt 50 -and $w -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 100
    $f = [L]::TopLevel([uint32]$p.Id, 'MdnsListener.Main')
    if ($f.Count -gt 0) { $w = $f[0] }
}
if ($w -eq [IntPtr]::Zero) { throw 'main window never appeared' }
try {
    Start-Sleep -Milliseconds 800
    $dpi = [L]::GetDpiForWindow($w)
    Write-Output "window dpi $dpi"
    $log = Pane $w 107; $conv = Pane $w 108; $tree = Pane $w 109; $hex = Pane $w 110
    Write-Output ("log {0}x{1}  conv {2}x{3}  tree {4}x{5}  hex {6}x{7}" -f (Width $log), (Height $log), (Width $conv), (Height $conv), (Width $tree), (Height $tree), (Width $hex), (Height $hex))

    # 1a. Vertical splitter: in the gap between the log and the tree, 150 px left.
    $d = 150
    $gx = [int](($log.R + $tree.L) / 2); $gy = [int](($log.T + $log.B) / 2)
    DragSplit $w $gx $gy ($gx - $d) $gy
    $log2 = Pane $w 107; $tree2 = Pane $w 109
    Write-Output ("vertical: log width {0} -> {1}, tree width {2} -> {3}" -f (Width $log), (Width $log2), (Width $tree), (Width $tree2))
    Verdict 'vertical splitter moves both panes' ([Math]::Abs((Width $log) - (Width $log2) - $d) -le 2 -and
        [Math]::Abs((Width $tree2) - (Width $tree) - $d) -le 2 -and (Width $conv) -ne (Width (Pane $w 108)))

    # 1b. Left splitter: between the log and the conversations, 100 px down.
    $log = $log2; $conv = Pane $w 108
    $gx = [int](($log.L + $log.R) / 2); $gy = $log.B + 3
    DragSplit $w $gx $gy $gx ($gy + 100)
    $log2 = Pane $w 107; $conv2 = Pane $w 108
    Write-Output ("left: log height {0} -> {1}, conv height {2} -> {3}" -f (Height $log), (Height $log2), (Height $conv), (Height $conv2))
    Verdict 'left splitter moves both panes' ([Math]::Abs((Height $log2) - (Height $log) - 100) -le 2 -and
        [Math]::Abs((Height $conv) - (Height $conv2) - 100) -le 2)

    # 1c. Right splitter: between the decode tree and the bytes, 100 px up.
    $tree = $tree2; $hex = Pane $w 110
    $gx = [int](($tree.L + $tree.R) / 2); $gy = $tree.B + 3
    DragSplit $w $gx $gy $gx ($gy - 100)
    $tree2 = Pane $w 109; $hex2 = Pane $w 110
    Write-Output ("right: tree height {0} -> {1}, hex height {2} -> {3}" -f (Height $tree), (Height $tree2), (Height $hex), (Height $hex2))
    Verdict 'right splitter moves both panes' ([Math]::Abs((Height $tree) - (Height $tree2) - 100) -le 2 -and
        [Math]::Abs((Height $hex2) - (Height $hex) - 100) -le 2)
    Capture $w $Png

    # 1d. Far past every edge: the clamp holds and every pane keeps some size.
    $log = Pane $w 107; $tree = Pane $w 109
    DragSplit $w ([int](($log.R + $tree.L) / 2)) ([int](($log.T + $log.B) / 2)) -5000 ([int](($log.T + $log.B) / 2))
    $log = Pane $w 107
    DragSplit $w ([int](($log.L + $log.R) / 2)) ($log.B + 3) ([int](($log.L + $log.R) / 2)) 5000
    $tree = Pane $w 109
    DragSplit $w ([int](($tree.L + $tree.R) / 2)) ($tree.B + 3) ([int](($tree.L + $tree.R) / 2)) -5000
    $all = 107, 108, 109, 110 | ForEach-Object { Pane $w $_ }
    $sizes = ($all | ForEach-Object { "{0}x{1}" -f (Width $_), (Height $_) }) -join '  '
    Write-Output "clamped: $sizes"
    Verdict 'clamped drags leave every pane showing' (@($all | Where-Object { (Width $_) -lt 40 -or (Height $_) -lt 40 }).Count -eq 0)
    Capture $w ($Png -replace '\.png$', '-clamped.png')

    # 2. DPI: to 96 and back, each to a suggested rectangle.
    $btn0 = Height (Pane $w 101)
    $col0 = [int][L]::SendMessageW([L]::GetDlgItem($w, 107), 0x101D, [IntPtr]5, [IntPtr]::Zero)   # LVM_GETCOLUMNWIDTH, summary
    $r0 = New-Object L+RECT; [L]::GetWindowRect($w, [ref]$r0) | Out-Null
    foreach ($step in @(@(96, 1100, 700), @($dpi, 1650, 1050))) {
        $to = $step[0]
        $s = New-Object L+RECT
        $s.L = $r0.L; $s.T = $r0.T; $s.R = $r0.L + $step[1]; $s.B = $r0.T + $step[2]
        [L]::ForgeDpi($w, $to, $s)
        Start-Sleep -Milliseconds 500
        $r = New-Object L+RECT; [L]::GetWindowRect($w, [ref]$r) | Out-Null
        $btn = Height (Pane $w 101)
        $col = [int][L]::SendMessageW([L]::GetDlgItem($w, 107), 0x101D, [IntPtr]5, [IntPtr]::Zero)
        $wantBtn = [int][Math]::Round(26 * $to / 96.0)
        $wantCol = [int][Math]::Round($col0 * $to / [double]$dpi)
        Write-Output ("dpi {0}: window {1}x{2}, button height {3} (want {4}), summary column {5} (want ~{6})" -f $to, ($r.R - $r.L), ($r.B - $r.T), $btn, $wantBtn, $col, $wantCol)
        Verdict "dpi $to window takes the suggested rect" (($r.L -eq $s.L) -and ($r.T -eq $s.T) -and ($r.R -eq $s.R) -and ($r.B -eq $s.B))
        Verdict "dpi $to controls rescale" ([Math]::Abs($btn - $wantBtn) -le 1 -and [Math]::Abs($col - $wantCol) -le 2)
        Capture $w ($Png -replace '\.png$', "-dpi$to.png")
    }
    Write-Output "button height at start $btn0"
    Verdict 'no dialogs' (([L]::TopLevel([uint32]$p.Id, '#32770')).Count -eq 0)
}
finally {
    if (-not $p.HasExited) {
        [L]::PostMessageW($w, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        $p.WaitForExit(5000) | Out-Null
    }
    Write-Output "exited: $($p.HasExited)"
}
Write-Output "failures: $script:fail"
exit $(if ($script:fail -eq 0) { 0 } else { 1 })
