[![release](https://img.shields.io/github/v/release/Flinterpop/MdnsListener)](https://github.com/Flinterpop/MdnsListener/releases/latest)

# MDNS Listener

A passive mDNS (multicast DNS, RFC 6762 / DNS-SD RFC 6763) listener for Windows. It logs every mDNS message it hears, summarises the traffic per source host, and decodes any message you click on into a field tree with a linked hex dump. Plain Win32, C++20, no dependencies.

**It never transmits.** It binds UDP 5353 shared (`SO_REUSEADDR`, alongside the Windows DNS client and Bonjour), joins `224.0.0.251` and `ff02::fb` on every interface that is up, and only receives.

## The window

| Pane | What it shows |
|---|---|
| **Log** (top left) | One row per datagram: number, time, source, query or response, length, a one-line summary, destination (from `IP_PKTINFO`) and interface. Responses are blue and malformed or truncated packets red. Holds the newest 20,000 packets. |
| **Conversations** (bottom left) | One row per source address: packets, queries, responses, bytes, malformed count, first and last seen, source ports, the host and service-instance names it announced, and the names it asked about. **Select a row to filter the log to that host**; **Show all** clears the filter. |
| **Sequence** (top right, second tab) | A message sequence chart of the exchange about the selected packet's names: every logged message that asks about, or answers for, any of them (up to 100 each side of it). Lifelines are the hosts plus the mDNS group. Queries go to the group. A multicast response is drawn to the host whose query for the same name it followed within 1 s, labelled with the delay and marked *inferred*, since multicast carries no addressee. Otherwise it is drawn to the group as an announcement, or as a goodbye when every answer has TTL 0. Unicast messages go to their real destination. Click an arrow, or use Up/Down, to decode that packet. |
| **Decode** (top right) | The selected packet as a tree: arrival and addressing, the header with every flag bit, then each question and record with its fields. It shows the QU and cache-flush bits, and decodes A, AAAA, PTR, CNAME, NS, DNAME, SRV, TXT, HINFO, MX, SOA, NSEC (type bitmaps) and OPT, including the EDNS0 Owner option. Other types are shown in hex. |
| **Bytes** (bottom right) | Hex dump of the packet. Selecting a tree line highlights the bytes it came from. |

Selecting a log row decodes it, charts its exchange, and selects its sender in **Conversations** without filtering the log. Clicking that conversation then filters to it.

The three gaps between the panes are splitters. **Copy decode** puts the tree and hex dump on the clipboard. **Pause** freezes the display but not the capture: packets keep arriving and are held (up to 20,000), the status line counts them, and **Resume** adds them all. **Stop/Start** closes and reopens the sockets, so nothing is captured while stopped. **Clear** empties the log and the conversations.

## Opening a capture

**Open capture…**, a file dropped on the window, or a path on the command line (`MdnsListener.exe capture.pcapng`) stops listening and shows the mDNS in a capture file instead, with every pane working as it does live. The title bar names the file, and the status line gives the mDNS count, the frame count and anything skipped. **Start** goes back to listening and drops the file's packets; so does **Clear**.

- **Formats:** classic pcap in either byte order, with microsecond or nanosecond timestamps; pcapng with any number of sections and interfaces, each with its own timestamp resolution and offset. The Interface column shows the pcapng interface description (Wireshark's "Wi-Fi"), else its name.
- **Link types:** Ethernet (up to two VLAN tags), BSD null/loopback (Npcap's loopback adapter), raw IPv4/IPv6, Linux cooked SLL and SLL2.
- **Kept:** IPv4 or IPv6 UDP to or from port 5353. IP fragments are counted and skipped, not reassembled. A datagram the capture snapped short is marked truncated and decoded as far as it goes.
- **Limits:** files up to 1 GiB; the first 20,000 mDNS packets are shown, and the status line says how many more there were. A file damaged part way through shows what came before the damage and says where the read stopped.

A malformed packet is decoded as far as it is valid, and the first fault is named (for example `compression pointer at offset 12 points forward to 32`). The decoder bounds every read, follows compression pointers iteratively, accepts only pointers that point backwards, and caps the steps per name, so a pointer loop terminates.

## Build

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The exe is static-CRT and needs no redistributable. First-party code builds `/W4 /WX`. The version lives only in `project(VERSION)` in `CMakeLists.txt`.

## Layout

| Path | Contents |
|---|---|
| `src/core/Capture.*` | pcap and pcapng reader: link layers, IP, UDP, and the mDNS datagrams out of them |
| `src/core/Dns.*` | Wire-format decoder: produces the structured message, the decode tree and the log summary |
| `src/core/Conversations.*` | Per-source-host summary table (bounded: 4,096 hosts, 64 names per list) |
| `src/core/HexDump.*` | Hex dump text, and the byte-range to character-range mapping used for highlighting |
| `src/core/Listener.*` | Sockets, group membership and the receive thread |
| `src/core/Sequence.*` | Sequence chart model: which messages relate, query/response matching, lifelines (capped at 16) |
| `src/gui/Main.cpp` | The window |
| `src/gui/SequenceView.*` | The chart window (GDI, double-buffered, scrolls both ways) |
| `src/gui/MdnsListener.ico` | The icon, generated by `tools/make_icon.py` (Pillow); regenerate it rather than edit it |
| `tests/test_mdns.cpp` | Decoder, hex-dump, conversation-table and 200,000-packet fuzz tests |
| `tests/test_capture.cpp` | Capture reader tests: both pcap byte orders and resolutions, multi-section multi-interface pcapng, every link type, fragments, snapped and damaged files, and a 100,000-file fuzz pass. `test_capture --read <files>` prints what the reader makes of real captures, for comparing with tshark |
| `tools/feed_mdns.py` | Bench feeder: a two-host exchange over the **loopback interface only**: queries (and optionally malformed packets) from 127.0.0.1, responses from 127.0.0.2 |
| `tools/drive_smoke.ps1` | GUI driver: launches its own instance and feeds it. It checks the count one-for-one, selects a row, a tree line, the Sequence tab and a conversation, and checks that Pause holds and Resume releases every packet. It captures PNGs into `build/claude-scratch/` and closes the instance. `-Exe` picks the build |
| `tools/drive_capture.ps1` | GUI driver for capture files: opens `-File` from the command line and again through the Open dialog, checks the counts against `-Expect` (an independent count, such as tshark's) and the log's rows, decodes the first packet, checks that Start returns to live, and that a non-capture raises exactly one warning |

## Power of 10 deviations

- The receive loop and the UI message pump are unbounded by design.
- `WSARecvMsg` can only be reached through an extension function pointer (`Listener::recvMsg_`), so the program has that one function pointer.
