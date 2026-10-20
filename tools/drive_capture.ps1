# Capture-file driver for MDNS Listener. Launches its own instances only,
# with posted messages only (no real input), and closes only what it started.
#
#   1. Command line: opens -File, checks the status line's counts against
#      -Expect (an independent count, e.g. tshark's) and the log's row count,
#      copies the first packet's decode and prints its frame lines.
#   2. Start: going live must drop the file's packets and say so.
#   3. Open capture...: drives the common dialog by messages (file name edit
#      id 1148, then IDOK) and checks the same counts again.
#   4. A file that is not a capture must raise exactly one warning box.
param(
    [string]$Exe = '',
    [Parameter(Mandatory = $true)][string]$File,
    [int]$Expect = -1,
    [string]$NotCapture = '',
    [string]$Png = ''
)
$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty in a param default under Windows PowerShell 5.1,
# which once sent the screenshots to C:\build; resolve the defaults here.
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Exe) { $Exe = Join-Path $repo 'build\Release\MdnsListener.exe' }
if (-not $NotCapture) { $NotCapture = Join-Path $repo 'README.md' }
if (-not $Png) { $Png = Join-Path $repo 'build\claude-scratch\capture.png' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class C {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    public struct RECT { public int L, T, R, B; }
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
    // The common dialog's file name edit is a descendant, not a child.
    public static IntPtr FileNameEdit(IntPtr dlg) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(dlg, (h, l) => {
            if (Cls(h) == "Edit" && GetDlgCtrlID(h) == 1148) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static string Text(IntPtr h) {
        var sb = new StringBuilder(2048);
        SendMessageW(h, 0x000D, (IntPtr)2048, sb);
        return sb.ToString();
    }
}
'@
[C]::SetProcessDPIAware() | Out-Null
Add-Type -AssemblyName System.Drawing
$File = (Resolve-Path $File).Path
$name = Split-Path $File -Leaf
$script:fail = 0
function Verdict([string]$what, [bool]$ok) {
    if (-not $ok) { $script:fail++ }
    Write-Output ("{0}: {1}" -f $what, $(if ($ok) { 'PASS' } else { 'FAIL' }))
}

function Launch([string]$arg) {
    $p = if ($arg) { Start-Process -FilePath (Resolve-Path $Exe) -ArgumentList "`"$arg`"" -PassThru }
         else { Start-Process -FilePath (Resolve-Path $Exe) -PassThru }
    $w = [IntPtr]::Zero
    for ($i = 0; $i -lt 50 -and $w -eq [IntPtr]::Zero; $i++) {
        Start-Sleep -Milliseconds 100
        $f = [C]::TopLevel([uint32]$p.Id, 'MdnsListener.Main')
        if ($f.Count -gt 0) { $w = $f[0] }
    }
    if ($w -eq [IntPtr]::Zero) { throw 'main window never appeared' }
    return @($p, $w)
}
function Close($p, $w) {
    if (-not $p.HasExited) {
        [C]::PostMessageW($w, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        $p.WaitForExit(5000) | Out-Null
    }
    Write-Output "exited: $($p.HasExited)"
}
function WaitStatus($w, [string]$pattern) {
    $s = ''
    for ($i = 0; $i -lt 100; $i++) {
        $s = [C]::Text([C]::GetDlgItem($w, 106))
        if ($s -match $pattern) { break }
        Start-Sleep -Milliseconds 100
    }
    return $s
}
function Capture($w, [string]$path) {
    $r = New-Object C+RECT
    [C]::GetWindowRect($w, [ref]$r) | Out-Null
    $bmp = New-Object System.Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $dc = $gfx.GetHdc()
    [C]::PrintWindow($w, $dc, 2) | Out-Null
    $gfx.ReleaseHdc($dc)
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    $bmp.Save($path)
    $gfx.Dispose(); $bmp.Dispose()
    Write-Output "captured $path"
}
function Key($w, [int]$id, [int]$vk) {
    $h = [C]::GetDlgItem($w, $id)
    [C]::PostMessageW($h, 0x0100, [IntPtr]$vk, [IntPtr]::Zero) | Out-Null
    [C]::PostMessageW($h, 0x0101, [IntPtr]$vk, [IntPtr]0xC0000001) | Out-Null
    Start-Sleep -Milliseconds 150
}
# The status line's counts, checked against -Expect and the log's rows.
function CheckCounts($w, [string]$label) {
    $s = WaitStatus $w 'mDNS in'
    Write-Output "status: $s"
    $m = [regex]::Match($s, '(\d+) mDNS in (\d+) frames')
    $mdns = [int]$m.Groups[1].Value
    $rows = [int][C]::SendMessageW([C]::GetDlgItem($w, 107), 0x1004, [IntPtr]::Zero, [IntPtr]::Zero)   # LVM_GETITEMCOUNT
    $pk = [int]([regex]::Match($s, '(\d+) packets').Groups[1].Value)
    Write-Output ("{0}: {1} mDNS read, {2} log rows, {3} packets counted, expected {4}" -f $label, $mdns, $rows, $pk, $Expect)
    Verdict "$label counts" ($m.Success -and $rows -eq [Math]::Min($mdns, 20000) -and $pk -eq $rows -and
        ($Expect -lt 0 -or $mdns -eq $Expect))
    Verdict "$label title names the file" ([C]::Text($w) -like "*$name*")
}

# 1. Command line.
$p, $w = Launch $File
try {
    CheckCounts $w 'command line'
    Verdict 'not listening' ([C]::Text([C]::GetDlgItem($w, 101)) -eq 'Start')
    Key $w 107 0x24   # Home: first row
    Start-Sleep -Milliseconds 300
    Set-Clipboard -Value 'empty'
    [C]::PostMessageW($w, 0x0111, [IntPtr]104, [C]::GetDlgItem($w, 104)) | Out-Null   # Copy decode
    Start-Sleep -Milliseconds 400
    $clip = (Get-Clipboard) -join "`n"
    $frame = ($clip -split "`n") | Where-Object { $_ -match '^(Packet 1:|\s+(Arrival|Source|Destination|Interface|Truncated):)' }
    $frame | ForEach-Object { Write-Output "decode> $($_.TrimEnd())" }
    Verdict 'first packet decoded' ($clip -match 'Packet 1:')
    Capture $w $Png
    Key $w 111 0x27   # Sequence tab
    Start-Sleep -Milliseconds 400
    Capture $w ($Png -replace '\.png$', '-sequence.png')
    Key $w 111 0x25
    Verdict 'no dialogs' (([C]::TopLevel([uint32]$p.Id, '#32770')).Count -eq 0)

    # 2. Start: back to live, the file's packets gone.
    [C]::PostMessageW([C]::GetDlgItem($w, 101), 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null   # BM_CLICK
    Start-Sleep -Milliseconds 600
    $s = [C]::Text([C]::GetDlgItem($w, 106))
    Write-Output "after Start: $s"
    Verdict 'Start leaves the file' (($s -notmatch 'mDNS in') -and ([C]::Text([C]::GetDlgItem($w, 101)) -eq 'Stop') -and
        ([C]::Text($w) -notlike "*$name*"))
    [C]::PostMessageW([C]::GetDlgItem($w, 101), 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 300

    # 3. Open capture... through the common dialog.
    [C]::PostMessageW([C]::GetDlgItem($w, 113), 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $dlg = [IntPtr]::Zero
    for ($i = 0; $i -lt 50 -and $dlg -eq [IntPtr]::Zero; $i++) {
        Start-Sleep -Milliseconds 100
        $d = [C]::TopLevel([uint32]$p.Id, '#32770')
        if ($d.Count -gt 0) { $dlg = $d[0] }
    }
    Verdict 'Open dialog appeared' ($dlg -ne [IntPtr]::Zero)
    if ($dlg -ne [IntPtr]::Zero) {
        $edit = [IntPtr]::Zero
        for ($i = 0; $i -lt 30 -and $edit -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 100; $edit = [C]::FileNameEdit($dlg) }
        [C]::SendMessageW($edit, 0x000C, [IntPtr]::Zero, $File) | Out-Null   # WM_SETTEXT
        [C]::PostMessageW($dlg, 0x0111, [IntPtr]1, [IntPtr]::Zero) | Out-Null   # IDOK
        Start-Sleep -Milliseconds 500
        CheckCounts $w 'Open dialog'
    }
    Verdict 'no dialogs after open' (([C]::TopLevel([uint32]$p.Id, '#32770')).Count -eq 0)

    # Clear: the file's figures and name must go with its packets.
    [C]::PostMessageW([C]::GetDlgItem($w, 102), 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 400
    $s = [C]::Text([C]::GetDlgItem($w, 106))
    Write-Output "after Clear: $s"
    Verdict 'Clear leaves the file' (($s -notmatch 'mDNS in') -and ($s -match '\b0 packets') -and ([C]::Text($w) -notlike "*$name*"))
}
finally { Close $p $w }

# 4. Not a capture: exactly one warning box, closed by us (it is ours).
$p, $w = Launch (Resolve-Path $NotCapture).Path
try {
    $boxes = @()
    for ($i = 0; $i -lt 30 -and $boxes.Count -eq 0; $i++) { Start-Sleep -Milliseconds 100; $boxes = [C]::TopLevel([uint32]$p.Id, '#32770') }
    Verdict 'bad file warns once' ($boxes.Count -eq 1)
    foreach ($b in $boxes) {
        $msg = [C]::Text([C]::GetDlgItem($b, 0xFFFF))
        Write-Output "warning box says: $msg"
        [C]::PostMessageW($b, 0x0111, [IntPtr]1, [IntPtr]::Zero) | Out-Null
    }
    Start-Sleep -Milliseconds 300
    Write-Output "status: $([C]::Text([C]::GetDlgItem($w, 106)))"
}
finally { Close $p $w }

Write-Output "failures: $script:fail"
exit $(if ($script:fail -eq 0) { 0 } else { 1 })
