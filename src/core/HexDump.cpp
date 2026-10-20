#include "HexDump.h"

#include <cassert>
#include <cstdio>

namespace mdns {

std::string HexDump(const uint8_t* data, size_t size)
{
    assert(data != nullptr || size == 0);
    std::string out;
    out.reserve((size / kHexBytesPerLine + 1) * kHexLineChars);
    for (size_t line = 0; line * kHexBytesPerLine < size; ++line) {
        const size_t base = line * kHexBytesPerLine;
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%04zX  ", base);
        out += buf;
        std::string ascii;
        for (size_t i = 0; i < kHexBytesPerLine; ++i) {
            if (base + i < size) {
                const uint8_t b = data[base + i];
                std::snprintf(buf, sizeof(buf), "%02X ", b);
                out += buf;
                ascii += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            } else {
                out += "   ";
            }
        }
        out += ' ';
        out += ascii;
        out += "\r\n";
    }
    assert(size == 0 || out.size() >= kHexLineChars - kHexBytesPerLine);
    return out;
}

bool HexSelection(size_t size, size_t offset, size_t length, size_t& first, size_t& last)
{
    if (length == 0 || offset >= size) {
        return false;
    }
    const size_t lastByte = (offset + length > size ? size : offset + length) - 1;
    assert(lastByte >= offset);
    first = (offset / kHexBytesPerLine) * kHexLineChars + 6 + (offset % kHexBytesPerLine) * 3;
    last = (lastByte / kHexBytesPerLine) * kHexLineChars + 6 + (lastByte % kHexBytesPerLine) * 3 + 2;
    assert(first < last);
    return true;
}

} // namespace mdns
