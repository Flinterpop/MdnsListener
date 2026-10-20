// MDNS Listener: main window.
//
//   +----------------------------------+-----------------------------+
//   | Log (virtual list view)          | [Decode | Sequence] tabs    |
//   |                                  | tree view / sequence chart  |
//   |----------------------------------|-----------------------------|
//   | Conversations (virtual list)     | Bytes (hex dump edit)       |
//   +----------------------------------+-----------------------------+
//
// The three gaps between the panes are splitters. Selecting a log row
// decodes that packet into the tree, charts the exchange about its names,
// and selects its sender's conversation; selecting a tree line highlights
// its bytes in the hex dump; clicking a conversation filters the log to it;
// clicking a chart arrow decodes that packet.
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>

#include "Conversations.h"
#include "Dns.h"
#include "HexDump.h"
#include "Listener.h"
#include "Sequence.h"
#include "SequenceView.h"
#include "version.h"

#include <algorithm>
#include <cassert>
#include <cwchar>
#include <deque>
#include <string>
#include <vector>

namespace {

constexpr UINT_PTR kTimerId = 1;
constexpr UINT kTimerMs = 150;
constexpr size_t kMaxLogEntries = 20000;
constexpr size_t kEvictBlock = 1000;
constexpr int kMaxTreeDepth = 8;
constexpr size_t kChartContext = 100;   // related messages charted each side of the selected one
constexpr wchar_t kClassName[] = L"MdnsListener.Main";

enum ControlId : int {
    IDC_PAUSE = 100,
    IDC_START = 101,
    IDC_CLEAR,
    IDC_SHOWALL,
    IDC_COPY,
    IDC_AUTOSCROLL,
    IDC_STATUS,
    IDC_LOG,
    IDC_CONV,
    IDC_TREE,
    IDC_HEX,
    IDC_TABS,
    IDC_SEQ,
};

struct LogEntry {
    uint64_t seq = 0;
    mdns::Packet pkt;
    std::wstring summary;
    mdns::NameSet names;            // what it asks about or answers for
    bool response = false;
    bool malformed = false;
};

enum class Drag { None, Vertical, Left, Right };

struct Column {
    const wchar_t* title;
    int width;   // at 96 dpi
    int format;
};

struct App {
    HINSTANCE inst = nullptr;
    HWND wnd = nullptr;
    HWND start = nullptr, pause = nullptr, clear = nullptr, showAll = nullptr, copy = nullptr, autoScroll = nullptr;
    HWND status = nullptr;
    HWND hdrLog = nullptr, hdrConv = nullptr, hdrDecode = nullptr, hdrHex = nullptr;
    HWND log = nullptr, conv = nullptr, tree = nullptr, hex = nullptr;
    HWND tabs = nullptr, seq = nullptr;
    HFONT ui = nullptr, mono = nullptr;
    UINT dpi = 96;

    mdns::Listener listener;
    std::string listenStatus;
    std::wstring lastStatus;

    // Pause freezes the display, not the capture: packets drained while
    // paused wait here and are added on resume.
    bool paused = false;
    std::vector<mdns::Packet> held;
    uint64_t heldDropped = 0;       // over the hold cap while paused

    std::deque<LogEntry> entries;
    uint64_t nextSeq = 1;
    std::vector<uint64_t> view;     // seq of each visible log row, ascending
    std::string filter;             // source address, empty for all
    mdns::ConversationTable convs;

    uint64_t shownSeq = 0;          // packet in the decode panel
    size_t shownSize = 0;
    std::vector<mdns::Node> shownNodes;
    bool syncing = false;           // selection being restored by code

    double splitX = 0.56, splitLeft = 0.62, splitRight = 0.58;
    RECT vSplit{}, lSplit{}, rSplit{}, content{}, leftArea{}, rightArea{};
    Drag drag = Drag::None;
};

App g;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

int Scale(int v) { return MulDiv(v, static_cast<int>(g.dpi), 96); }

std::wstring Wide(const std::string& s)
{
    if (s.empty()) {
        return std::wstring();
    }
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) {
        return std::wstring();
    }
    std::wstring w(static_cast<size_t>(n), L'\0');
    const int r = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    assert(r == n);
    return r == n ? w : std::wstring();
}

std::wstring TimeText(uint64_t ticks, bool withDate)
{
    FILETIME utc{static_cast<DWORD>(ticks & 0xFFFFFFFFu), static_cast<DWORD>(ticks >> 32)};
    FILETIME local{};
    SYSTEMTIME st{};
    if (ticks == 0 || !FileTimeToLocalFileTime(&utc, &local) || !FileTimeToSystemTime(&local, &st)) {
        return L"";
    }
    wchar_t buf[64];
    if (withDate) {
        swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u.%03u", st.wYear, st.wMonth, st.wDay, st.wHour,
                   st.wMinute, st.wSecond, st.wMilliseconds);
    } else {
        swprintf_s(buf, L"%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    }
    return buf;
}

std::wstring Endpoint(const mdns::Packet& p)
{
    const std::wstring addr = Wide(p.source);
    const std::wstring port = std::to_wstring(p.sourcePort);
    return p.ipv6 ? L"[" + addr + L"]:" + port : addr + L":" + port;
}

const LogEntry* FindEntry(uint64_t seq)
{
    if (g.entries.empty() || seq < g.entries.front().seq) {
        return nullptr;
    }
    const uint64_t i = seq - g.entries.front().seq;
    if (i >= g.entries.size()) {
        return nullptr;
    }
    const LogEntry& e = g.entries[static_cast<size_t>(i)];
    assert(e.seq == seq);
    return &e;
}

void CopyOut(NMLVDISPINFOW* di, const std::wstring& s)
{
    assert(di != nullptr);
    if (di->item.pszText != nullptr && di->item.cchTextMax > 0) {
        wcsncpy_s(di->item.pszText, static_cast<size_t>(di->item.cchTextMax), s.c_str(), _TRUNCATE);
    }
}

HWND MakeChild(const wchar_t* cls, const wchar_t* text, DWORD style, DWORD exStyle, int id)
{
    assert(cls != nullptr);
    HWND h = CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g.wnd,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g.inst, nullptr);
    assert(h != nullptr);
    return h;
}

void AddColumns(HWND lv, const Column* cols, int count)
{
    assert(lv != nullptr && cols != nullptr);
    for (int i = 0; i < count; ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        c.fmt = cols[i].format;
        c.cx = Scale(cols[i].width);
        c.pszText = const_cast<wchar_t*>(cols[i].title);
        const int r = ListView_InsertColumn(lv, i, &c);
        assert(r == i);
        (void)r;
    }
}

// ---------------------------------------------------------------------------
// Fonts and layout
// ---------------------------------------------------------------------------

void ApplyFonts()
{
    HFONT oldUi = g.ui;
    HFONT oldMono = g.mono;
    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, g.dpi)) {
        g.ui = CreateFontIndirectW(&ncm.lfMessageFont);
    }
    g.mono = CreateFontW(-MulDiv(9, static_cast<int>(g.dpi), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                         FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         FIXED_PITCH | FF_MODERN, L"Consolas");
    const HWND uiControls[] = {g.start, g.pause, g.clear, g.showAll, g.copy, g.autoScroll, g.status, g.hdrLog,
                               g.hdrConv, g.hdrDecode, g.hdrHex, g.log, g.conv, g.tabs, g.seq};
    for (HWND h : uiControls) {
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g.ui), TRUE);
    }
    SendMessageW(g.tree, WM_SETFONT, reinterpret_cast<WPARAM>(g.mono), TRUE);
    SendMessageW(g.hex, WM_SETFONT, reinterpret_cast<WPARAM>(g.mono), TRUE);
    if (oldUi != nullptr) {
        DeleteObject(oldUi);
    }
    if (oldMono != nullptr) {
        DeleteObject(oldMono);
    }
}

void Place(HWND h, int x, int y, int w, int hgt)
{
    MoveWindow(h, x, y, std::max(w, 0), std::max(hgt, 0), TRUE);
}

// Header, pane, splitter, header, pane, stacked in `area`. `head1` and
// `pane1` receive the first header's and pane's rectangles.
void LayoutPair(const RECT& area, double frac, HWND h1, HWND c1, HWND h2, HWND c2, RECT& split, RECT& head1,
                RECT& pane1)
{
    const int gap = Scale(6);
    const int hh = Scale(20);
    const int w = static_cast<int>(area.right - area.left);
    const int avail = std::max(static_cast<int>(area.bottom - area.top) - gap - 2 * hh, 0);
    const int topH = static_cast<int>(avail * frac);
    int y = area.top;
    head1 = {area.left, y, area.right, y + hh};
    Place(h1, area.left, y, w, hh);
    y += hh;
    pane1 = {area.left, y, area.right, y + topH};
    Place(c1, area.left, y, w, topH);
    y += topH;
    split = {area.left, y, area.right, y + gap};
    y += gap;
    Place(h2, area.left, y, w, hh);
    y += hh;
    Place(c2, area.left, y, w, area.bottom - y);
}

void Layout()
{
    RECT rc{};
    if (!GetClientRect(g.wnd, &rc)) {
        return;
    }
    const int m = Scale(6);
    const int gap = Scale(6);
    const int bh = Scale(26);
    int x = m;
    const int y = m;
    const struct { HWND h; int w; } bar[] = {
        {g.start, 80}, {g.pause, 80}, {g.clear, 80}, {g.showAll, 110}, {g.copy, 110}, {g.autoScroll, 100}};
    for (const auto& b : bar) {
        Place(b.h, x, y, Scale(b.w), bh);
        x += Scale(b.w) + m;
    }
    Place(g.status, x, y, rc.right - m - x, bh);
    const int top = y + bh + m;
    g.content = {m, top, std::max(static_cast<int>(rc.right) - m, m + 2 * gap),
                 std::max(static_cast<int>(rc.bottom) - m, top + 2 * gap)};
    const int width = g.content.right - g.content.left;
    const int leftW = static_cast<int>((width - gap) * g.splitX);
    g.leftArea = {g.content.left, top, g.content.left + leftW, g.content.bottom};
    g.rightArea = {g.leftArea.right + gap, top, g.content.right, g.content.bottom};
    g.vSplit = {g.leftArea.right, top, g.rightArea.left, g.content.bottom};
    RECT head{}, pane{};
    LayoutPair(g.leftArea, g.splitLeft, g.hdrLog, g.log, g.hdrConv, g.conv, g.lSplit, head, pane);
    LayoutPair(g.rightArea, g.splitRight, g.hdrDecode, g.tree, g.hdrHex, g.hex, g.rSplit, head, pane);
    // The right-hand header row holds the Decode / Sequence tabs, then the caption.
    const int tabW = Scale(170);
    const int tabTop = static_cast<int>(head.top) - Scale(4);
    Place(g.tabs, head.left, tabTop, tabW, static_cast<int>(head.bottom) - tabTop + Scale(2));
    Place(g.hdrDecode, head.left + tabW + m, head.top, head.right - head.left - tabW - m, head.bottom - head.top);
    Place(g.seq, pane.left, pane.top, pane.right - pane.left, pane.bottom - pane.top);
    InvalidateRect(g.wnd, nullptr, TRUE);
}

double Clamp(double v) { return std::min(std::max(v, 0.12), 0.88); }

void DragTo(POINT pt)
{
    const int hh = Scale(20);
    const int gap = Scale(6);
    if (g.drag == Drag::Vertical) {
        const int width = std::max(static_cast<int>(g.content.right - g.content.left - gap), 1);
        g.splitX = Clamp(static_cast<double>(pt.x - g.content.left) / width);
    } else {
        const RECT& a = (g.drag == Drag::Left) ? g.leftArea : g.rightArea;
        const int avail = std::max(static_cast<int>(a.bottom - a.top - gap - 2 * hh), 1);
        const double f = Clamp(static_cast<double>(pt.y - a.top - hh) / avail);
        (g.drag == Drag::Left ? g.splitLeft : g.splitRight) = f;
    }
    Layout();
}

// ---------------------------------------------------------------------------
// Log, conversations, status
// ---------------------------------------------------------------------------

void SetLogHeader()
{
    std::wstring s = L"Log";
    if (!g.filter.empty()) {
        s += L"  —  filtered to " + Wide(g.filter) + L"  (Show all clears the filter)";
    }
    SetWindowTextW(g.hdrLog, s.c_str());
}

// Re-selects the decoded packet's row after the row indices moved.
void RestoreSelection()
{
    g.syncing = true;
    ListView_SetItemState(g.log, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    const auto it = std::lower_bound(g.view.begin(), g.view.end(), g.shownSeq);
    if (g.shownSeq != 0 && it != g.view.end() && *it == g.shownSeq) {
        const int row = static_cast<int>(it - g.view.begin());
        ListView_SetItemState(g.log, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    g.syncing = false;
}

void RebuildView()
{
    g.view.clear();
    for (const LogEntry& e : g.entries) {
        if (g.filter.empty() || e.pkt.source == g.filter) {
            g.view.push_back(e.seq);
        }
    }
    ListView_SetItemCountEx(g.log, static_cast<int>(g.view.size()), 0);
    RestoreSelection();
    SetLogHeader();
    InvalidateRect(g.log, nullptr, TRUE);
}

void SetFilter(const std::string& address)
{
    g.filter = address;
    RebuildView();
    if (!g.view.empty() && address.empty()) {
        ListView_EnsureVisible(g.log, static_cast<int>(g.view.size()) - 1, FALSE);
    }
}

// Drops the oldest log entries once the log is over its cap. Returns true
// when anything was dropped, since row indices then shift.
bool Evict()
{
    if (g.entries.size() <= kMaxLogEntries) {
        return false;
    }
    const size_t drop = g.entries.size() - kMaxLogEntries + kEvictBlock;
    for (size_t i = 0; i < drop && !g.entries.empty(); ++i) {
        g.entries.pop_front();
    }
    const uint64_t first = g.entries.empty() ? g.nextSeq : g.entries.front().seq;
    g.view.erase(g.view.begin(), std::lower_bound(g.view.begin(), g.view.end(), first));
    assert(g.entries.size() <= kMaxLogEntries);
    return true;
}

void UpdateStatus()
{
    std::wstring s = Wide(g.listenStatus);
    if (!g.listener.Running()) {
        s = L"Stopped.  " + s;
    }
    s += L"  |  " + std::to_wstring(g.nextSeq - 1) + L" packets, " +
         std::to_wstring(g.convs.Items().size()) + L" hosts";
    const uint64_t dropped = g.listener.Dropped() + g.heldDropped;
    if (dropped > 0) {
        s += L", " + std::to_wstring(dropped) + L" dropped";
    }
    if (g.paused) {
        s = L"PAUSED, " + std::to_wstring(g.held.size()) + L" held.  " + s;
    }
    if (s != g.lastStatus) {
        SetWindowTextW(g.status, s.c_str());
        g.lastStatus = s;
    }
}

// Holds what the listener has queued while paused, up to the log's own cap.
void Hold()
{
    std::vector<mdns::Packet> batch;
    g.listener.Drain(batch);
    for (mdns::Packet& p : batch) {
        if (g.held.size() >= kMaxLogEntries) {
            ++g.heldDropped;
        } else {
            g.held.push_back(std::move(p));
        }
    }
    assert(g.held.size() <= kMaxLogEntries);
    UpdateStatus();
}

void IngestBatch(std::vector<mdns::Packet>& batch)
{
    if (batch.empty()) {
        UpdateStatus();
        return;
    }
    for (mdns::Packet& p : batch) {
        mdns::Message m;
        mdns::Decode(p.data.data(), p.data.size(), m);
        LogEntry e;
        e.seq = g.nextSeq++;
        e.response = m.IsResponse();
        e.malformed = !m.error.empty() || p.truncated;
        e.summary = (p.truncated ? L"[TRUNCATED] " : L"") + Wide(mdns::Summarize(m));
        e.names = mdns::CollectNames(m);
        g.convs.Add(p.source, p.sourcePort, m, p.data.size(), p.time);
        if (g.filter.empty() || g.filter == p.source) {
            g.view.push_back(e.seq);
        }
        e.pkt = std::move(p);
        g.entries.push_back(std::move(e));
    }
    const bool shifted = Evict();
    ListView_SetItemCountEx(g.log, static_cast<int>(g.view.size()),
                            shifted ? 0 : (LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL));
    if (shifted) {
        RestoreSelection();
    }
    if (Button_GetCheck(g.autoScroll) == BST_CHECKED && !g.view.empty()) {
        ListView_EnsureVisible(g.log, static_cast<int>(g.view.size()) - 1, FALSE);
    }
    ListView_SetItemCountEx(g.conv, static_cast<int>(g.convs.Items().size()),
                            LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    InvalidateRect(g.conv, nullptr, FALSE);
    UpdateStatus();
}

void Ingest()
{
    if (g.paused) {
        Hold();
        return;
    }
    std::vector<mdns::Packet> batch;
    g.listener.Drain(batch);
    IngestBatch(batch);
}

void TogglePause()
{
    g.paused = Button_GetCheck(g.pause) == BST_CHECKED;
    SetWindowTextW(g.pause, g.paused ? L"Resume" : L"Pause");
    if (!g.paused) {
        std::vector<mdns::Packet> batch;
        batch.swap(g.held);
        g.listener.Drain(batch);
        IngestBatch(batch);
        assert(g.held.empty());
    }
    UpdateStatus();
}

void LogDispInfo(NMLVDISPINFOW* di)
{
    assert(di != nullptr);
    const int row = di->item.iItem;
    if ((di->item.mask & LVIF_TEXT) == 0 || row < 0 || static_cast<size_t>(row) >= g.view.size()) {
        return;
    }
    const LogEntry* e = FindEntry(g.view[static_cast<size_t>(row)]);
    if (e == nullptr) {
        return;
    }
    switch (di->item.iSubItem) {
    case 0: CopyOut(di, std::to_wstring(e->seq)); break;
    case 1: CopyOut(di, TimeText(e->pkt.time, false)); break;
    case 2: CopyOut(di, Endpoint(e->pkt)); break;
    case 3: CopyOut(di, e->response ? L"Response" : L"Query"); break;
    case 4: CopyOut(di, std::to_wstring(e->pkt.data.size())); break;
    case 5: CopyOut(di, e->summary); break;
    case 6: CopyOut(di, Wide(e->pkt.destination)); break;
    default: CopyOut(di, Wide(g.listener.InterfaceName(e->pkt.ifIndex))); break;
    }
}

void ConvDispInfo(NMLVDISPINFOW* di)
{
    assert(di != nullptr);
    const auto& items = g.convs.Items();
    const int row = di->item.iItem;
    if ((di->item.mask & LVIF_TEXT) == 0 || row < 0 || static_cast<size_t>(row) >= items.size()) {
        return;
    }
    const mdns::Conversation& c = items[static_cast<size_t>(row)];
    switch (di->item.iSubItem) {
    case 0: CopyOut(di, Wide(c.address)); break;
    case 1: CopyOut(di, Wide(c.hostName)); break;
    case 2: CopyOut(di, std::to_wstring(c.packets)); break;
    case 3: CopyOut(di, std::to_wstring(c.queries)); break;
    case 4: CopyOut(di, std::to_wstring(c.responses)); break;
    case 5: CopyOut(di, std::to_wstring(c.bytes)); break;
    case 6: CopyOut(di, std::to_wstring(c.malformed)); break;
    case 7: CopyOut(di, TimeText(c.firstSeen, false)); break;
    case 8: CopyOut(di, TimeText(c.lastSeen, false)); break;
    case 9: CopyOut(di, Wide(mdns::JoinNames(c.ports))); break;
    case 10: CopyOut(di, Wide(mdns::JoinNames(c.announced))); break;
    default: CopyOut(di, Wide(mdns::JoinNames(c.asked))); break;
    }
}

LRESULT LogCustomDraw(NMLVCUSTOMDRAW* cd)
{
    assert(cd != nullptr);
    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) {
        return CDRF_NOTIFYITEMDRAW;
    }
    if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
        const size_t row = static_cast<size_t>(cd->nmcd.dwItemSpec);
        const LogEntry* e = row < g.view.size() ? FindEntry(g.view[row]) : nullptr;
        cd->clrText = GetSysColor(COLOR_WINDOWTEXT);
        if (e != nullptr && e->malformed) {
            cd->clrText = RGB(192, 0, 0);
        } else if (e != nullptr && e->response) {
            cd->clrText = RGB(0, 70, 140);
        }
    }
    return CDRF_DODEFAULT;
}

// ---------------------------------------------------------------------------
// Decode panel
// ---------------------------------------------------------------------------

void AddFrameNodes(const LogEntry& e, std::vector<mdns::Node>& out)
{
    const mdns::Packet& p = e.pkt;
    auto add = [&out](int depth, const std::wstring& text) {
        mdns::Node n;
        n.depth = static_cast<uint8_t>(depth);
        const int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len > 1) {
            n.text.resize(static_cast<size_t>(len - 1));
            WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, n.text.data(), len, nullptr, nullptr);
        }
        out.push_back(std::move(n));
    };
    add(0, L"Packet " + std::to_wstring(e.seq) + L": " + std::to_wstring(p.data.size()) + L" bytes over " +
               (p.ipv6 ? L"IPv6" : L"IPv4"));
    add(1, L"Arrival: " + TimeText(p.time, true));
    add(1, L"Source: " + Endpoint(p));
    add(1, L"Destination: " + Wide(p.destination) + L" port 5353");
    add(1, L"Interface: " + Wide(g.listener.InterfaceName(p.ifIndex)) + L" (index " +
               std::to_wstring(p.ifIndex) + L")");
    if (p.truncated) {
        add(1, L"Truncated: datagram was larger than the receive buffer");
    }
}

void FillTree()
{
    SendMessageW(g.tree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(g.tree);
    HTREEITEM parents[kMaxTreeDepth + 1] = {TVI_ROOT};
    std::vector<HTREEITEM> expand;
    int valid = 0;   // deepest depth that has a parent
    for (size_t i = 0; i < g.shownNodes.size(); ++i) {
        const int depth = std::min({static_cast<int>(g.shownNodes[i].depth), valid, kMaxTreeDepth - 1});
        std::wstring text = Wide(g.shownNodes[i].text);
        TVINSERTSTRUCTW ins{};
        ins.hParent = parents[depth];
        ins.hInsertAfter = TVI_LAST;
        ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        ins.item.pszText = text.data();
        ins.item.lParam = static_cast<LPARAM>(i);
        HTREEITEM h = TreeView_InsertItem(g.tree, &ins);
        if (h == nullptr) {
            break;
        }
        parents[depth + 1] = h;
        valid = depth + 1;
        if (depth == 0) {
            expand.push_back(h);
        }
    }
    for (HTREEITEM h : expand) {
        TreeView_Expand(g.tree, h, TVE_EXPAND);
    }
    SendMessageW(g.tree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.tree, nullptr, TRUE);
}

// Selects (and scrolls to) a host's conversation without filtering the log.
void SelectConversation(const std::string& address)
{
    const int row = g.convs.Find(address);
    g.syncing = true;
    ListView_SetItemState(g.conv, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (row >= 0) {
        ListView_SetItemState(g.conv, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(g.conv, row, FALSE);
    }
    g.syncing = false;
}

seqview::Kind ViewKind(mdns::ArrowKind k)
{
    switch (k) {
    case mdns::ArrowKind::Query: return seqview::Kind::Query;
    case mdns::ArrowKind::Response: return seqview::Kind::Response;
    case mdns::ArrowKind::Announcement: return seqview::Kind::Announcement;
    case mdns::ArrowKind::Goodbye: return seqview::Kind::Goodbye;
    default: return seqview::Kind::Unicast;
    }
}

std::wstring NamesCaption(const mdns::NameSet& n)
{
    std::vector<std::string> all = n.asked;
    all.insert(all.end(), n.owners.begin(), n.owners.end());
    all.insert(all.end(), n.targets.begin(), n.targets.end());
    std::wstring s;
    size_t shown = 0;
    for (size_t i = 0; i < all.size() && shown < 3; ++i) {
        if (std::find(all.begin(), all.begin() + static_cast<ptrdiff_t>(i), all[i]) == all.begin() + static_cast<ptrdiff_t>(i)) {
            s += (shown == 0 ? L"" : L", ") + Wide(all[i]);
            ++shown;
        }
    }
    return s.empty() ? L"(no names)" : s;
}

seqview::Chart ToView(const mdns::SeqChart& chart)
{
    seqview::Chart vc;
    for (const std::string& lane : chart.lifelines) {
        vc.titles.push_back(Wide(lane));
        const int c = g.convs.Find(lane);
        std::wstring sub;
        if (lane == mdns::kGroupLifeline) {
            sub = L"224.0.0.251 / ff02::fb";
        } else if (c >= 0) {
            sub = Wide(g.convs.Items()[static_cast<size_t>(c)].hostName);
        }
        vc.subtitles.push_back(sub);
    }
    assert(chart.lifelines.size() <= static_cast<size_t>(mdns::kMaxLifelines));
    for (const mdns::SeqArrow& a : chart.arrows) {
        seqview::Arrow va;
        va.seq = a.seq;
        va.from = a.from;
        va.to = a.to;
        va.kind = ViewKind(a.kind);
        va.left = L"#" + std::to_wstring(a.seq) + L"  " + TimeText(a.time, false);
        va.label = Wide(a.label);
        va.note = Wide(a.note);
        vc.arrows.push_back(std::move(va));
    }
    return vc;
}

// Charts the messages that share a name with the selected one, up to
// kChartContext either side of it.
void BuildChart(const LogEntry& sel)
{
    std::vector<size_t> related;
    size_t selPos = 0;
    for (size_t i = 0; i < g.entries.size(); ++i) {
        const LogEntry& e = g.entries[i];
        if (e.seq == sel.seq) {
            selPos = related.size();
            related.push_back(i);
        } else if (mdns::Shares(sel.names, e.names)) {
            related.push_back(i);
        }
    }
    const size_t from = selPos > kChartContext ? selPos - kChartContext : 0;
    const size_t to = std::min(related.size(), selPos + kChartContext + 1);
    std::vector<mdns::Message> msgs(to - from);   // sized once: SeqMessage points into it
    std::vector<mdns::SeqMessage> in;
    for (size_t k = from; k < to; ++k) {
        const LogEntry& e = g.entries[related[k]];
        mdns::Message& m = msgs[k - from];
        mdns::Decode(e.pkt.data.data(), e.pkt.data.size(), m);
        mdns::SeqMessage sm;
        sm.seq = e.seq;
        sm.time = e.pkt.time;
        sm.source = e.pkt.source;
        sm.destination = e.pkt.destination;
        sm.msg = &m;
        sm.names = e.names;
        in.push_back(std::move(sm));
    }
    seqview::Chart vc = ToView(mdns::BuildSequence(in));
    assert(vc.arrows.size() == in.size());
    vc.caption = L"Exchange about " + NamesCaption(sel.names) + L":  " + std::to_wstring(in.size()) + L" of " +
                 std::to_wstring(related.size()) + L" related messages.  Response arrows to a querier are inferred.";
    seqview::SetChart(g.seq, std::move(vc));
    seqview::Select(g.seq, sel.seq);
}

void ShowDecode(uint64_t seq, bool rebuildChart)
{
    const LogEntry* e = FindEntry(seq);
    if (e == nullptr) {
        return;
    }
    mdns::Message m;
    mdns::Decode(e->pkt.data.data(), e->pkt.data.size(), m);
    g.shownSeq = seq;
    g.shownSize = e->pkt.data.size();
    g.shownNodes.clear();
    AddFrameNodes(*e, g.shownNodes);
    if (m.tree.empty() && !m.error.empty()) {
        mdns::Node n;
        n.text = "Malformed: " + m.error;
        g.shownNodes.push_back(std::move(n));
    }
    g.shownNodes.insert(g.shownNodes.end(), m.tree.begin(), m.tree.end());
    FillTree();
    SetWindowTextW(g.hex, Wide(mdns::HexDump(e->pkt.data.data(), e->pkt.data.size())).c_str());
    SetWindowTextW(g.hdrDecode, (L"Packet " + std::to_wstring(seq) + L" from " + Endpoint(e->pkt)).c_str());
    SelectConversation(e->pkt.source);
    if (rebuildChart) {
        BuildChart(*e);
    } else {
        seqview::Select(g.seq, seq);
    }
}

void ShowPane(int tab)
{
    ShowWindow(g.tree, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g.seq, tab == 1 ? SW_SHOW : SW_HIDE);
}

// A chart arrow was clicked: decode that packet and select its log row,
// keeping the chart as it is.
void OnArrowClicked(uint64_t seq)
{
    ShowDecode(seq, false);
    const auto it = std::lower_bound(g.view.begin(), g.view.end(), seq);
    if (it != g.view.end() && *it == seq) {
        RestoreSelection();
        ListView_EnsureVisible(g.log, static_cast<int>(it - g.view.begin()), FALSE);
    }
}

void HighlightBytes(LPARAM nodeIndex)
{
    if (nodeIndex < 0 || static_cast<size_t>(nodeIndex) >= g.shownNodes.size()) {
        return;
    }
    const mdns::Node& n = g.shownNodes[static_cast<size_t>(nodeIndex)];
    size_t first = 0, last = 0;
    if (!mdns::HexSelection(g.shownSize, n.offset, n.length, first, last)) {
        SendMessageW(g.hex, EM_SETSEL, 0, 0);
        return;
    }
    // Scroll the end into view first, then the start, so the start wins.
    SendMessageW(g.hex, EM_SETSEL, last, last);
    SendMessageW(g.hex, EM_SCROLLCARET, 0, 0);
    SendMessageW(g.hex, EM_SETSEL, first, first);
    SendMessageW(g.hex, EM_SCROLLCARET, 0, 0);
    SendMessageW(g.hex, EM_SETSEL, first, last);
}

bool PutClipboard(const std::wstring& text)
{
    if (!OpenClipboard(g.wnd)) {
        return false;
    }
    bool ok = false;
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    void* p = (mem != nullptr) ? GlobalLock(mem) : nullptr;
    if (p != nullptr) {
        memcpy(p, text.c_str(), bytes);
        GlobalUnlock(mem);
        ok = EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, mem) != nullptr;
    }
    if (!ok && mem != nullptr) {
        GlobalFree(mem);
    }
    CloseClipboard();
    return ok;
}

void CopyDecode()
{
    if (g.shownNodes.empty()) {
        MessageBeep(MB_ICONWARNING);
        return;
    }
    std::wstring text;
    for (const mdns::Node& n : g.shownNodes) {
        text += std::wstring(static_cast<size_t>(n.depth) * 4, L' ') + Wide(n.text) + L"\r\n";
    }
    const LogEntry* e = FindEntry(g.shownSeq);
    if (e != nullptr) {
        text += L"\r\n" + Wide(mdns::HexDump(e->pkt.data.data(), e->pkt.data.size()));
    }
    if (!PutClipboard(text)) {
        MessageBoxW(g.wnd, L"Could not put the decode on the clipboard.", L"MDNS Listener", MB_ICONWARNING);
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

void StartStop()
{
    if (g.listener.Running()) {
        g.listener.Stop();
        SetWindowTextW(g.start, L"Start");
    } else if (g.listener.Start(g.listenStatus)) {
        SetWindowTextW(g.start, L"Stop");
    } else {
        MessageBoxW(g.wnd, (L"Could not listen for mDNS.\r\n\r\n" + Wide(g.listenStatus)).c_str(),
                    L"MDNS Listener", MB_ICONERROR);
    }
    UpdateStatus();
}

void ClearAll()
{
    g.entries.clear();
    g.held.clear();
    g.heldDropped = 0;
    g.view.clear();
    g.convs.Clear();
    g.filter.clear();
    g.nextSeq = 1;
    g.shownSeq = 0;
    g.shownSize = 0;
    g.shownNodes.clear();
    ListView_SetItemCountEx(g.log, 0, 0);
    ListView_SetItemCountEx(g.conv, 0, 0);
    TreeView_DeleteAllItems(g.tree);
    SetWindowTextW(g.hex, L"");
    SetWindowTextW(g.hdrDecode, L"Select a log row");
    seqview::SetChart(g.seq, seqview::Chart{});
    SetLogHeader();
    UpdateStatus();
}

void ShowAll()
{
    g.syncing = true;
    ListView_SetItemState(g.conv, -1, 0, LVIS_SELECTED);
    g.syncing = false;
    SetFilter(std::string());
}

void CreateControls()
{
    g.start = MakeChild(L"BUTTON", L"Stop", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_START);
    g.pause = MakeChild(L"BUTTON", L"Pause", BS_AUTOCHECKBOX | BS_PUSHLIKE | WS_TABSTOP, 0, IDC_PAUSE);
    g.clear = MakeChild(L"BUTTON", L"Clear", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_CLEAR);
    g.showAll = MakeChild(L"BUTTON", L"Show all", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_SHOWALL);
    g.copy = MakeChild(L"BUTTON", L"Copy decode", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_COPY);
    g.autoScroll = MakeChild(L"BUTTON", L"Auto-scroll", BS_AUTOCHECKBOX | WS_TABSTOP, 0, IDC_AUTOSCROLL);
    Button_SetCheck(g.autoScroll, BST_CHECKED);
    g.status = MakeChild(L"STATIC", L"", SS_LEFT | SS_CENTERIMAGE | SS_ENDELLIPSIS | SS_NOPREFIX, 0, IDC_STATUS);
    g.hdrLog = MakeChild(L"STATIC", L"Log", SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX, 0, 0);
    g.hdrConv = MakeChild(L"STATIC", L"Conversations  —  one row per source host; select one to filter the log",
                          SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX, 0, 0);
    g.hdrDecode = MakeChild(L"STATIC", L"Select a log row", SS_LEFT | SS_CENTERIMAGE | SS_ENDELLIPSIS | SS_NOPREFIX, 0, 0);
    g.tabs = MakeChild(WC_TABCONTROLW, L"", WS_TABSTOP | WS_CLIPSIBLINGS, 0, IDC_TABS);
    const wchar_t* tabNames[] = {L"Decode", L"Sequence"};
    for (int i = 0; i < 2; ++i) {
        TCITEMW ti{};
        ti.mask = TCIF_TEXT;
        ti.pszText = const_cast<wchar_t*>(tabNames[i]);
        const int r = TabCtrl_InsertItem(g.tabs, i, &ti);
        assert(r == i);
        (void)r;
    }
    g.seq = seqview::Create(g.wnd, IDC_SEQ, g.inst);
    assert(g.seq != nullptr);
    g.hdrHex = MakeChild(L"STATIC", L"Bytes", SS_LEFT | SS_CENTERIMAGE, 0, 0);
    const DWORD lvStyle = LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP;
    g.log = MakeChild(WC_LISTVIEWW, L"", lvStyle, WS_EX_CLIENTEDGE, IDC_LOG);
    g.conv = MakeChild(WC_LISTVIEWW, L"", lvStyle, WS_EX_CLIENTEDGE, IDC_CONV);
    g.tree = MakeChild(WC_TREEVIEWW, L"",
                       TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | WS_TABSTOP,
                       WS_EX_CLIENTEDGE, IDC_TREE);
    g.hex = MakeChild(L"EDIT", L"",
                      ES_MULTILINE | ES_READONLY | ES_NOHIDESEL | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL |
                          WS_HSCROLL | WS_TABSTOP,
                      WS_EX_CLIENTEDGE, IDC_HEX);
    const DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP;
    ListView_SetExtendedListViewStyle(g.log, ex);
    ListView_SetExtendedListViewStyle(g.conv, ex);
    static const Column kLog[] = {
        {L"No.", 50, LVCFMT_RIGHT},     {L"Time", 85, LVCFMT_LEFT},         {L"Source", 150, LVCFMT_LEFT},
        {L"Kind", 65, LVCFMT_LEFT},     {L"Len", 45, LVCFMT_RIGHT},         {L"Summary", 700, LVCFMT_LEFT},
        {L"Destination", 105, LVCFMT_LEFT}, {L"Interface", 130, LVCFMT_LEFT}};
    static const Column kConv[] = {
        {L"Host address", 210, LVCFMT_LEFT}, {L"Host name", 170, LVCFMT_LEFT}, {L"Packets", 65, LVCFMT_RIGHT},
        {L"Queries", 65, LVCFMT_RIGHT},      {L"Responses", 75, LVCFMT_RIGHT}, {L"Bytes", 75, LVCFMT_RIGHT},
        {L"Malformed", 75, LVCFMT_RIGHT},    {L"First seen", 95, LVCFMT_LEFT}, {L"Last seen", 95, LVCFMT_LEFT},
        {L"Ports", 70, LVCFMT_LEFT},         {L"Announced", 420, LVCFMT_LEFT}, {L"Asked about", 420, LVCFMT_LEFT}};
    AddColumns(g.log, kLog, static_cast<int>(std::size(kLog)));
    AddColumns(g.conv, kConv, static_cast<int>(std::size(kConv)));
    SendMessageW(g.hex, EM_SETLIMITTEXT, 0, 0);
}

void RescaleColumns(HWND lv, UINT oldDpi, UINT newDpi)
{
    const int count = Header_GetItemCount(ListView_GetHeader(lv));
    for (int i = 0; i < count && i < 64; ++i) {
        const int w = ListView_GetColumnWidth(lv, i);
        ListView_SetColumnWidth(lv, i, MulDiv(w, static_cast<int>(newDpi), static_cast<int>(oldDpi)));
    }
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

LRESULT OnNotify(NMHDR* nm)
{
    assert(nm != nullptr);
    if (nm->idFrom == IDC_LOG) {
        if (nm->code == LVN_GETDISPINFOW) {
            LogDispInfo(reinterpret_cast<NMLVDISPINFOW*>(nm));
        } else if (nm->code == NM_CUSTOMDRAW) {
            return LogCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(nm));
        } else if (nm->code == LVN_ITEMCHANGED && !g.syncing) {
            const auto* lv = reinterpret_cast<NMLISTVIEW*>(nm);
            if ((lv->uNewState & LVIS_SELECTED) && lv->iItem >= 0 &&
                static_cast<size_t>(lv->iItem) < g.view.size()) {
                ShowDecode(g.view[static_cast<size_t>(lv->iItem)], true);
            }
        }
    } else if (nm->idFrom == IDC_CONV) {
        if (nm->code == LVN_GETDISPINFOW) {
            ConvDispInfo(reinterpret_cast<NMLVDISPINFOW*>(nm));
        } else if (nm->code == NM_CLICK) {
            // A click filters even when the row is already selected, which it
            // is whenever the log selected it for us.
            const int row = reinterpret_cast<NMITEMACTIVATE*>(nm)->iItem;
            const auto& items = g.convs.Items();
            if (row >= 0 && static_cast<size_t>(row) < items.size()) {
                SetFilter(items[static_cast<size_t>(row)].address);
            }
        } else if (nm->code == LVN_ITEMCHANGED && !g.syncing) {
            const auto* lv = reinterpret_cast<NMLISTVIEW*>(nm);
            const auto& items = g.convs.Items();
            if ((lv->uNewState & LVIS_SELECTED) && lv->iItem >= 0 && static_cast<size_t>(lv->iItem) < items.size()) {
                SetFilter(items[static_cast<size_t>(lv->iItem)].address);
            }
        }
    } else if (nm->idFrom == IDC_TABS && nm->code == TCN_SELCHANGE) {
        ShowPane(TabCtrl_GetCurSel(g.tabs));
    } else if (nm->idFrom == IDC_TREE && nm->code == TVN_SELCHANGEDW) {
        HighlightBytes(reinterpret_cast<NMTREEVIEWW*>(nm)->itemNew.lParam);
    }
    return 0;
}

bool OnSetCursor(HWND hit, LPARAM lp)
{
    if (hit != g.wnd || LOWORD(lp) != HTCLIENT) {
        return false;
    }
    POINT pt{};
    if (!GetCursorPos(&pt) || !ScreenToClient(g.wnd, &pt)) {
        return false;
    }
    if (PtInRect(&g.vSplit, pt)) {
        SetCursor(LoadCursorW(nullptr, IDC_SIZEWE));
        return true;
    }
    if (PtInRect(&g.lSplit, pt) || PtInRect(&g.rSplit, pt)) {
        SetCursor(LoadCursorW(nullptr, IDC_SIZENS));
        return true;
    }
    return false;
}

void OnLButtonDown(POINT pt)
{
    g.drag = PtInRect(&g.vSplit, pt)   ? Drag::Vertical
             : PtInRect(&g.lSplit, pt) ? Drag::Left
             : PtInRect(&g.rSplit, pt) ? Drag::Right
                                       : Drag::None;
    if (g.drag != Drag::None) {
        SetCapture(g.wnd);
    }
}

void OnCreate(HWND wnd)
{
    g.wnd = wnd;
    g.dpi = GetDpiForWindow(wnd);
    CreateControls();
    ApplyFonts();
    SetLogHeader();
    Layout();
    StartStop();
    SetTimer(wnd, kTimerId, kTimerMs, nullptr);
}

void OnDpiChanged(HWND wnd, UINT dpi, const RECT* suggested)
{
    assert(suggested != nullptr);
    const UINT old = g.dpi;
    g.dpi = dpi;
    ApplyFonts();
    RescaleColumns(g.log, old, dpi);
    RescaleColumns(g.conv, old, dpi);
    SetWindowPos(wnd, nullptr, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
}

LRESULT CALLBACK WndProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: OnCreate(wnd); return 0;
    case WM_SIZE: Layout(); return 0;
    case WM_TIMER: Ingest(); return 0;
    case WM_NOTIFY: return OnNotify(reinterpret_cast<NMHDR*>(lp));
    case WM_SETCURSOR:
        if (OnSetCursor(reinterpret_cast<HWND>(wp), lp)) {
            return TRUE;
        }
        break;
    case WM_LBUTTONDOWN: OnLButtonDown({GET_X_LPARAM(lp), GET_Y_LPARAM(lp)}); return 0;
    case WM_MOUSEMOVE:
        if (g.drag != Drag::None) {
            DragTo({GET_X_LPARAM(lp), GET_Y_LPARAM(lp)});
        }
        return 0;
    case WM_LBUTTONUP:
    case WM_CAPTURECHANGED:
        if (g.drag != Drag::None) {
            g.drag = Drag::None;
            ReleaseCapture();
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_START: StartStop(); return 0;
        case IDC_PAUSE: TogglePause(); return 0;
        case IDC_CLEAR: ClearAll(); return 0;
        case IDC_SHOWALL: ShowAll(); return 0;
        case IDC_COPY: CopyDecode(); return 0;
        default: break;
        }
        break;
    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
        mmi->ptMinTrackSize = {Scale(800), Scale(480)};
        return 0;
    }
    case WM_DPICHANGED: OnDpiChanged(wnd, HIWORD(wp), reinterpret_cast<const RECT*>(lp)); return 0;
    case seqview::kMsgArrowClicked: OnArrowClicked(static_cast<uint64_t>(wp)); return 0;
    case WM_DESTROY:
        KillTimer(wnd, kTimerId);
        g.listener.Stop();
        PostQuitMessage(0);
        return 0;
    default: break;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

} // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show)
{
    g.inst = inst;
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_STANDARD_CLASSES};
    if (!InitCommonControlsEx(&icc)) {
        return 1;
    }
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(nullptr, L"Winsock could not be started.", L"MDNS Listener", MB_ICONERROR);
        return 1;
    }
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClassName;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    if (RegisterClassExW(&wc) == 0 || !seqview::Register(inst)) {
        WSACleanup();
        return 1;
    }
    const int sys = static_cast<int>(GetDpiForSystem());
    HWND wnd = CreateWindowExW(0, kClassName, L"MDNS Listener " MDNSL_VERSION_W,
                               WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                               MulDiv(1400, sys, 96), MulDiv(860, sys, 96), nullptr, nullptr, inst, nullptr);
    if (wnd == nullptr) {
        WSACleanup();
        return 1;
    }
    ShowWindow(wnd, show);
    UpdateWindow(wnd);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {   // the UI pump: unbounded by design
        if (!IsDialogMessageW(wnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    WSACleanup();
    return static_cast<int>(msg.wParam);
}
