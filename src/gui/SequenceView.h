// Message sequence chart window: lifelines across, one arrow per message
// down, scrolling both ways. Clicking an arrow (or Up/Down) selects it and
// sends kMsgArrowClicked to the parent with the packet's seq in wParam.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace seqview {

constexpr UINT kMsgArrowClicked = WM_APP + 1;
constexpr wchar_t kClassName[] = L"MdnsListener.Sequence";

enum class Kind : uint8_t { Query, Response, Announcement, Goodbye, Unicast };

struct Arrow {
    uint64_t seq = 0;
    int from = 0;
    int to = 0;
    Kind kind = Kind::Query;
    std::wstring left;    // row title, e.g. "#12  10:50:37.825"
    std::wstring label;
    std::wstring note;
};

struct Chart {
    std::wstring caption;
    std::vector<std::wstring> titles;      // one per lifeline
    std::vector<std::wstring> subtitles;   // same length
    std::vector<Arrow> arrows;
};

bool Register(HINSTANCE inst);
HWND Create(HWND parent, int id, HINSTANCE inst);
void SetChart(HWND view, Chart chart);
void Select(HWND view, uint64_t seq);   // highlight and scroll into view; no notification

} // namespace seqview
