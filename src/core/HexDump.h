// Hex dump text for the decode panel, and the mapping from a byte range to
// the characters that show it, so a selected decode line can highlight its
// bytes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace mdns {

constexpr size_t kHexBytesPerLine = 16;
constexpr size_t kHexLineChars = 6 + kHexBytesPerLine * 3 + 1 + kHexBytesPerLine + 2;  // incl. CRLF

// "0000  45 00 ... 3F  E.......?" lines, CRLF-terminated.
std::string HexDump(const uint8_t* data, size_t size);

// Character range [first, last) of the hex digits for bytes
// [offset, offset + length) in HexDump(size bytes). False when the range is
// empty or outside the dump.
bool HexSelection(size_t size, size_t offset, size_t length, size_t& first, size_t& last);

} // namespace mdns
