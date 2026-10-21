#include "SequenceView.h"

#include <windowsx.h>

#include <algorithm>
#include <cassert>
#include <new>

namespace seqview {
namespace {

constexpr int kMaxLanes = 64;

struct State {
    Chart chart;
    uint64_t selected = 0;
    int scrollX = 0;
    int scrollY = 0;
    HFONT font = nullptr;
};

State* Get(HWND h)
{
    return reinterpret_cast<State*>(GetWindowLongPtrW(h, GWLP_USERDATA));
}

int S(HWND h, int v) { return MulDiv(v, static_cast<int>(GetDpiForWindow(h)), 96); }

struct Geometry {
    int captionH, headerH, rowH, leftW, laneW, contentW, contentH, top;
};

Geometry Measure(HWND h, const State& st)
{
    RECT rc{};
    GetClientRect(h, &rc);
    Geometry g{};
    g.captionH = S(h, 22);
    g.headerH = S(h, 44);
    g.rowH = S(h, 42);
    g.leftW = S(h, 115);
    g.top = g.captionH + g.headerH;
    const int lanes = std::max(static_cast<int>(st.chart.titles.size()), 1);
    g.laneW = std::max(S(h, 150), (static_cast<int>(rc.right) - g.leftW) / lanes);
    g.contentW = g.leftW + lanes * g.laneW;
    g.contentH = g.top + static_cast<int>(st.chart.arrows.size()) * g.rowH + S(h, 8);
    return g;
}

int LaneX(const Geometry& g, const State& st, int lane)
{
    assert(lane >= 0 && lane < kMaxLanes);
    return g.leftW + g.laneW * lane + g.laneW / 2 - st.scrollX;
}

void UpdateScrollBars(HWND h, State& st)
{
    RECT rc{};
    GetClientRect(h, &rc);
    const Geometry g = Measure(h, st);
    st.scrollX = std::clamp(st.scrollX, 0, std::max(g.contentW - static_cast<int>(rc.right), 0));
    st.scrollY = std::clamp(st.scrollY, 0, std::max(g.contentH - static_cast<int>(rc.bottom), 0));
    SCROLLINFO si{sizeof(si), SIF_ALL | SIF_DISABLENOSCROLL};
    si.nMin = 0;
    si.nMax = g.contentW - 1;
    si.nPage = static_cast<UINT>(rc.right);
    si.nPos = st.scrollX;
    SetScrollInfo(h, SB_HORZ, &si, TRUE);
    si.nMax = g.contentH - 1;
    si.nPage = static_cast<UINT>(rc.bottom);
    si.nPos = st.scrollY;
    SetScrollInfo(h, SB_VERT, &si, TRUE);
}

COLORREF KindColor(Kind k)
{
    switch (k) {
    case Kind::Query: return RGB(30, 30, 30);
    case Kind::Response: return RGB(0, 80, 170);
    case Kind::Announcement: return RGB(0, 125, 110);
    case Kind::Goodbye: return RGB(130, 130, 130);
    default: return RGB(130, 40, 160);
    }
}

void DrawHead(HDC dc, int x, int y, int dir, int size)
{
    assert(dir == 1 || dir == -1);
    POINT pts[3] = {{x, y}, {x - dir * size, y - size / 2}, {x - dir * size, y + size / 2}};
    Polygon(dc, pts, 3);
}

// One line of text on a patch of the row's own background, just as wide as
// the text, so the dotted lifelines do not run through it.
void DrawLabel(HDC dc, const std::wstring& s, const RECT& box, UINT vAlign, COLORREF fg, COLORREF bg)
{
    assert(vAlign == DT_TOP || vAlign == DT_BOTTOM);
    if (s.empty() || box.right <= box.left) {
        return;
    }
    RECT calc = box;
    const int ht = DrawTextW(dc, s.c_str(), -1, &calc, DT_SINGLELINE | DT_CALCRECT | DT_NOPREFIX);
    assert(ht >= 0);
    const int w = std::min(static_cast<int>(calc.right - calc.left), static_cast<int>(box.right - box.left));
    RECT patch{(box.left + box.right - w) / 2, 0, 0, 0};
    patch.right = patch.left + w;
    patch.top = (vAlign == DT_BOTTOM) ? std::max(box.bottom - ht, box.top) : box.top;
    patch.bottom = (vAlign == DT_BOTTOM) ? box.bottom : std::min(box.top + ht, box.bottom);
    HBRUSH b = CreateSolidBrush(bg);
    if (b != nullptr) {
        FillRect(dc, &patch, b);
        DeleteObject(b);
    }
    SetTextColor(dc, fg);
    RECT r = box;
    DrawTextW(dc, s.c_str(), -1, &r, DT_SINGLELINE | vAlign | DT_CENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
}

void DrawArrow(HDC dc, HWND h, const Geometry& g, const State& st, const Arrow& a, int rowTop, COLORREF bg)
{
    const int x1 = LaneX(g, st, a.from);
    const int x2 = LaneX(g, st, a.to);
    const int y = rowTop + g.rowH / 2 + S(h, 2);
    const COLORREF c = KindColor(a.kind);

    // Text first, so the arrow's own line stays on top of the label's patch.
    // Text may use the half-lanes either side of the arrow, so a message
    // between neighbouring lifelines still reads.
    const int lo = std::min(x1, x2) - g.laneW / 2;
    const int hi = std::max(x1, x2) + g.laneW / 2;
    const RECT label{lo + S(h, 4), rowTop + S(h, 1), hi - S(h, 4), y - S(h, 2)};
    DrawLabel(dc, a.label, label, DT_BOTTOM, c, bg);
    const RECT note{lo + S(h, 4), y + S(h, 3), hi - S(h, 4), rowTop + g.rowH};
    DrawLabel(dc, a.note, note, DT_TOP, RGB(110, 110, 110), bg);

    const bool dashed = (a.kind == Kind::Announcement || a.kind == Kind::Goodbye);
    HPEN pen = CreatePen(dashed ? PS_DOT : PS_SOLID, dashed ? 1 : S(h, 2), c);
    HBRUSH brush = CreateSolidBrush(c);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    const int head = S(h, 9);
    if (x1 == x2) {   // to itself: a small loop
        const int w = S(h, 28);
        MoveToEx(dc, x1, y - S(h, 6), nullptr);
        LineTo(dc, x1 + w, y - S(h, 6));
        LineTo(dc, x1 + w, y + S(h, 6));
        LineTo(dc, x1 + head, y + S(h, 6));
        DrawHead(dc, x1, y + S(h, 6), -1, head);
    } else {
        const int dir = (x2 > x1) ? 1 : -1;
        MoveToEx(dc, x1, y, nullptr);
        LineTo(dc, x2 - dir * head, y);
        DrawHead(dc, x2, y, dir, head);
    }
    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
}

void PaintRows(HDC dc, HWND h, const Geometry& g, const State& st, const RECT& rc)
{
    const int count = static_cast<int>(st.chart.arrows.size());
    const int first = std::max((st.scrollY) / g.rowH, 0);
    const int last = std::min(first + (static_cast<int>(rc.bottom) / g.rowH) + 2, count);
    for (int r = first; r < last; ++r) {
        const Arrow& a = st.chart.arrows[static_cast<size_t>(r)];
        const int top = g.top + r * g.rowH - st.scrollY;
        const COLORREF lite = RGB(220, 235, 252);
        const bool selected = (a.seq == st.selected);
        if (selected) {
            RECT band{0, top, rc.right, top + g.rowH};
            FillRect(dc, &band, GetSysColorBrush(COLOR_HIGHLIGHT));
            HBRUSH b = CreateSolidBrush(lite);
            InflateRect(&band, 0, -1);
            FillRect(dc, &band, b);
            DeleteObject(b);
        }
        RECT left{S(h, 6) - st.scrollX, top, g.leftW - S(h, 4) - st.scrollX, top + g.rowH};
        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
        DrawTextW(dc, a.left.c_str(), -1, &left, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS | DT_NOPREFIX);
        DrawArrow(dc, h, g, st, a, top, selected ? lite : GetSysColor(COLOR_WINDOW));
    }
}

void PaintLifelines(HDC dc, const Geometry& g, const State& st, const RECT& rc)
{
    HPEN pen = CreatePen(PS_DOT, 1, RGB(160, 160, 160));
    HGDIOBJ old = SelectObject(dc, pen);
    const int lanes = std::min(static_cast<int>(st.chart.titles.size()), kMaxLanes);
    for (int i = 0; i < lanes; ++i) {
        const int x = LaneX(g, st, i);
        MoveToEx(dc, x, g.top, nullptr);
        LineTo(dc, x, rc.bottom);
    }
    SelectObject(dc, old);
    DeleteObject(pen);
}

void PaintHeader(HDC dc, HWND h, const Geometry& g, const State& st, const RECT& rc)
{
    RECT band{0, 0, rc.right, g.top};
    FillRect(dc, &band, GetSysColorBrush(COLOR_BTNFACE));
    RECT cap{S(h, 6), 0, rc.right - S(h, 6), g.captionH};
    SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
    DrawTextW(dc, st.chart.caption.c_str(), -1, &cap, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS | DT_NOPREFIX);
    const int lanes = std::min(static_cast<int>(st.chart.titles.size()), kMaxLanes);
    for (int i = 0; i < lanes; ++i) {
        const int x = LaneX(g, st, i);
        RECT box{x - g.laneW / 2 + S(h, 6), g.captionH + S(h, 2), x + g.laneW / 2 - S(h, 6), g.top - S(h, 4)};
        FillRect(dc, &box, GetSysColorBrush(COLOR_WINDOW));
        FrameRect(dc, &box, GetSysColorBrush(COLOR_BTNSHADOW));
        RECT t1{box.left + 2, box.top + 1, box.right - 2, (box.top + box.bottom) / 2 + 1};
        RECT t2{box.left + 2, t1.bottom - 1, box.right - 2, box.bottom - 1};
        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
        DrawTextW(dc, st.chart.titles[static_cast<size_t>(i)].c_str(), -1, &t1,
                  DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        SetTextColor(dc, RGB(90, 90, 90));
        DrawTextW(dc, st.chart.subtitles[static_cast<size_t>(i)].c_str(), -1, &t2,
                  DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
}

void OnPaint(HWND h, State& st)
{
    PAINTSTRUCT ps{};
    HDC wdc = BeginPaint(h, &ps);
    RECT rc{};
    GetClientRect(h, &rc);
    HDC dc = CreateCompatibleDC(wdc);
    HBITMAP bmp = CreateCompatibleBitmap(wdc, std::max(static_cast<int>(rc.right), 1), std::max(static_cast<int>(rc.bottom), 1));
    if (dc != nullptr && bmp != nullptr) {
        HGDIOBJ oldBmp = SelectObject(dc, bmp);
        HGDIOBJ oldFont = SelectObject(dc, st.font != nullptr ? st.font : GetStockObject(DEFAULT_GUI_FONT));
        SetBkMode(dc, TRANSPARENT);
        FillRect(dc, &rc, GetSysColorBrush(COLOR_WINDOW));
        const Geometry g = Measure(h, st);
        if (st.chart.arrows.empty()) {
            RECT msg = rc;
            SetTextColor(dc, RGB(110, 110, 110));
            DrawTextW(dc, st.chart.caption.empty() ? L"Select a log row to chart its exchange." : st.chart.caption.c_str(),
                      -1, &msg, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
        } else {
            PaintLifelines(dc, g, st, rc);
            PaintRows(dc, h, g, st, rc);
            PaintHeader(dc, h, g, st, rc);
        }
        BitBlt(wdc, 0, 0, rc.right, rc.bottom, dc, 0, 0, SRCCOPY);
        SelectObject(dc, oldFont);
        SelectObject(dc, oldBmp);
    }
    if (bmp != nullptr) {
        DeleteObject(bmp);
    }
    if (dc != nullptr) {
        DeleteDC(dc);
    }
    EndPaint(h, &ps);
}

void Scroll(HWND h, State& st, int bar, WPARAM wp)
{
    SCROLLINFO si{sizeof(si), SIF_ALL};
    GetScrollInfo(h, bar, &si);
    const int line = S(h, 42);
    int pos = si.nPos;
    switch (LOWORD(wp)) {
    case SB_LINEUP: pos -= line; break;
    case SB_LINEDOWN: pos += line; break;
    case SB_PAGEUP: pos -= static_cast<int>(si.nPage); break;
    case SB_PAGEDOWN: pos += static_cast<int>(si.nPage); break;
    case SB_THUMBTRACK:
    case SB_THUMBPOSITION: pos = si.nTrackPos; break;
    case SB_TOP: pos = 0; break;
    case SB_BOTTOM: pos = si.nMax; break;
    default: break;
    }
    (bar == SB_VERT ? st.scrollY : st.scrollX) = pos;
    UpdateScrollBars(h, st);
    InvalidateRect(h, nullptr, FALSE);
}

int IndexOf(const State& st, uint64_t seq)
{
    for (size_t i = 0; i < st.chart.arrows.size(); ++i) {
        if (st.chart.arrows[i].seq == seq) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

void EnsureVisible(HWND h, State& st, int row)
{
    if (row < 0) {
        return;
    }
    RECT rc{};
    GetClientRect(h, &rc);
    const Geometry g = Measure(h, st);
    const int top = row * g.rowH;
    const int visible = std::max(static_cast<int>(rc.bottom) - g.top, g.rowH);
    if (top < st.scrollY) {
        st.scrollY = top;
    } else if (top + g.rowH > st.scrollY + visible) {
        st.scrollY = top + g.rowH - visible;
    }
    UpdateScrollBars(h, st);
}

void Choose(HWND h, State& st, int row)
{
    if (row < 0 || static_cast<size_t>(row) >= st.chart.arrows.size()) {
        return;
    }
    st.selected = st.chart.arrows[static_cast<size_t>(row)].seq;
    EnsureVisible(h, st, row);
    InvalidateRect(h, nullptr, FALSE);
    SendMessageW(GetParent(h), kMsgArrowClicked, static_cast<WPARAM>(st.selected), 0);
}

LRESULT CALLBACK Proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    State* st = Get(h);
    switch (msg) {
    case WM_NCCREATE: {
        auto* fresh = new (std::nothrow) State();
        if (fresh == nullptr) {
            return FALSE;
        }
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(fresh));
        break;
    }
    case WM_NCDESTROY:   // the last message: nothing below may touch st after this
        delete st;
        SetWindowLongPtrW(h, GWLP_USERDATA, 0);
        return DefWindowProcW(h, msg, wp, lp);
    default:
        break;
    }
    if (st == nullptr) {
        return DefWindowProcW(h, msg, wp, lp);
    }
    switch (msg) {
    case WM_PAINT: OnPaint(h, *st); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SIZE: UpdateScrollBars(h, *st); InvalidateRect(h, nullptr, FALSE); return 0;
    case WM_SETFONT: st->font = reinterpret_cast<HFONT>(wp); if (LOWORD(lp)) InvalidateRect(h, nullptr, FALSE); return 0;
    case WM_VSCROLL: Scroll(h, *st, SB_VERT, wp); return 0;
    case WM_HSCROLL: Scroll(h, *st, SB_HORZ, wp); return 0;
    case WM_MOUSEWHEEL:
        st->scrollY -= GET_WHEEL_DELTA_WPARAM(wp) * S(h, 42) * 3 / WHEEL_DELTA;
        UpdateScrollBars(h, *st);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_LBUTTONDOWN: {
        SetFocus(h);
        const Geometry g = Measure(h, *st);
        const int y = GET_Y_LPARAM(lp);
        if (y >= g.top) {
            Choose(h, *st, (y - g.top + st->scrollY) / g.rowH);
        }
        return 0;
    }
    case WM_GETDLGCODE: return DLGC_WANTARROWS;
    case WM_KEYDOWN: {
        const int row = IndexOf(*st, st->selected);
        if (wp == VK_UP) Choose(h, *st, row < 0 ? 0 : row - 1);
        else if (wp == VK_DOWN) Choose(h, *st, row + 1);
        else if (wp == VK_HOME) Choose(h, *st, 0);
        else if (wp == VK_END) Choose(h, *st, static_cast<int>(st->chart.arrows.size()) - 1);
        return 0;
    }
    case WM_SETFOCUS:
    case WM_KILLFOCUS: InvalidateRect(h, nullptr, FALSE); return 0;
    default: return DefWindowProcW(h, msg, wp, lp);
    }
}

} // namespace

bool Register(HINSTANCE inst)
{
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = Proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kClassName;
    return RegisterClassExW(&wc) != 0;
}

HWND Create(HWND parent, int id, HINSTANCE inst)
{
    assert(parent != nullptr);
    return CreateWindowExW(WS_EX_CLIENTEDGE, kClassName, L"", WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_TABSTOP,
                           0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), inst, nullptr);
}

void SetChart(HWND view, Chart chart)
{
    State* st = Get(view);
    if (st == nullptr) {
        return;
    }
    assert(chart.titles.size() == chart.subtitles.size());
    st->chart = std::move(chart);
    st->scrollX = 0;
    st->scrollY = 0;
    UpdateScrollBars(view, *st);
    InvalidateRect(view, nullptr, FALSE);
}

void Select(HWND view, uint64_t seq)
{
    State* st = Get(view);
    if (st == nullptr) {
        return;
    }
    st->selected = seq;
    EnsureVisible(view, *st, IndexOf(*st, seq));
    InvalidateRect(view, nullptr, FALSE);
}

} // namespace seqview
