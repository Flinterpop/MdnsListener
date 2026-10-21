[![release](https://img.shields.io/github/v/release/Flinterpop/MdnsListener)](https://github.com/Flinterpop/MdnsListener/releases/latest)

# MDNS Listener

A passive mDNS (multicast DNS, RFC 6762 / DNS-SD RFC 6763) listener and capture-file viewer for Windows. It logs every mDNS message it hears, or every one in a pcap or pcapng file, summarises the traffic per source host, decodes any message you click on into a field tree with a linked hex dump, and charts the exchange it belongs to as a message sequence. Plain Win32, C++20, no dependencies.

**It never transmits.** Live, it binds UDP 5353 shared (`SO_REUSEADDR`, alongside the Windows DNS client and Bonjour), joins `224.0.0.251` and `ff02::fb` on every interface that is up, and only receives. Opening a capture file uses no network at all.

## The window

| Pane | What it shows |
|---|---|
| **Log** (top left) | One row per datagram: number, time, source, query or response, length, a one-line summary, destination and interface. Live, the destination comes from `IP_PKTINFO`; from a file, from the IP header. Responses are blue, and malformed or truncated packets red. Holds 20,000 packets: the newest live, the first 20,000 of a file. |
| **Conversations** (bottom left) | One row per source address: packets, queries, responses, bytes, malformed count, first and last seen, source ports, the host and service-instance names it announced, and the names it asked about. **Select a row to filter the log to that host**; **Show all** clears the filter. |
| **Decode** (top right) | The selected packet as a tree: arrival, addressing and interface, the header with every flag bit, then each question and record with its fields. It shows the QU and cache-flush bits, and decodes A, AAAA, PTR, CNAME, NS, DNAME, SRV, TXT, HINFO, MX, SOA, NSEC (type bitmaps) and OPT, including the EDNS0 Owner option. Other types are shown in hex. |
| **Sequence** (top right, second tab) | A message sequence chart of the exchange about the selected packet's names: every logged message that asks about, or answers for, any of them (up to 100 each side of it). Lifelines are the hosts (up to 16) plus the mDNS group. Queries go to the group. A multicast response is drawn to the host whose query for the same name it followed within 1 s, labelled with the delay and marked *inferred*, since multicast carries no addressee. Otherwise it is drawn to the group as an announcement, or as a goodbye when every answer has TTL 0. Unicast messages go to their real destination. Click an arrow, or use Up/Down, to decode that packet. |
| **Bytes** (bottom right) | Hex dump of the packet. Selecting a tree line highlights the bytes it came from. |

Selecting a log row decodes it, charts its exchange, and selects its sender in **Conversations** without filtering the log. Clicking that conversation then filters to it. The three gaps between the panes are splitters.

| Button | What it does |
|---|---|
| **Open capture…** | Shows the mDNS in a pcap or pcapng file instead of listening (below). A file dropped on the window, or a path on the command line, does the same |
| **Stop / Start** | Closes and reopens the sockets; nothing is captured while stopped. After a file, **Start** drops the file's packets and goes back to listening |
| **Pause / Resume** | Freezes the display, not the capture: packets keep arriving and are held (up to 20,000), the status line counts them, and **Resume** adds them all |
| **Clear** | Empties the log, the conversations, the decode and the chart; after a file, it also leaves the file |
| **Show all** | Clears the conversation filter |
| **Copy decode** | Puts the decode tree and the hex dump on the clipboard |
| **Auto-scroll** | Keeps the newest row in view |

A malformed packet is decoded as far as it is valid, and the first fault is named (for example `compression pointer at offset 12 points forward to 32`). The decoder bounds every read, follows compression pointers iteratively, accepts only pointers that point backwards, and caps the steps per name, so a pointer loop terminates. A **truncated** packet is one of which only part arrived: live, larger than the 64 KiB receive buffer; from a file, cut short by the capture's snap length.

## Opening a capture

**Open capture…**, a file dropped on the window, or a path on the command line (`MdnsListener.exe capture.pcapng`) stops listening and shows the mDNS in a capture file, with every pane working as it does live. The title bar names the file, and the status line gives the mDNS count, the frame count, and anything skipped. A file that is not a capture is refused with a message saying why, and nothing else changes: the file is read before listening stops, so whatever was showing, live or another file, is still there. A refused file named on the command line starts listening instead, as a start without one would.

- **Formats:** classic pcap in either byte order, with microsecond or nanosecond timestamps; pcapng with any number of sections and interfaces, each with its own timestamp resolution and offset. The Interface column shows the pcapng interface description (Wireshark's "Wi-Fi"), else its name, else "interface *N*"; for a classic pcap, which names no interfaces, it shows "capture".
- **Link types:** Ethernet (up to two VLAN tags), BSD null/loopback (Npcap's loopback adapter), raw IPv4/IPv6, Linux cooked SLL and SLL2. Frames on any other link type are counted and skipped.
- **Kept:** IPv4 or IPv6 UDP to or from port 5353, past any IPv6 hop-by-hop, routing and destination-options headers. IP fragments are counted and skipped, not reassembled.
- **Times:** shown in local time, as live. A pcapng simple packet block carries no timestamp, so its time is blank.
- **Limits:** files up to 1 GiB; the first 20,000 mDNS packets are shown, and the status line says how many more there were. A file damaged part way through shows what came before the damage and says where the read stopped.

## Build

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The exe is static-CRT and needs no redistributable. First-party code builds `/W4 /WX`. The version lives only in `project(VERSION)` in `CMakeLists.txt`, from which `version.h` and the version resource are generated.

## Testing

- **`ctest`** runs both unit suites: `test_mdns` (decoder, hex dump, conversations, sequence model, 200,000-packet decoder fuzz) and `test_capture` (the capture reader, with a 100,000-file fuzz pass).
- **Live:** `tools\drive_smoke.ps1 -Exe <exe>` launches its own instance, feeds it over loopback with `tools/feed_mdns.py`, and checks the count one-for-one, the panes, the filter and Pause.
- **Capture files:** the reader is checked against Wireshark rather than only against files built by its own tests. Record the feeder with `dumpcap -i \Device\NPF_Loopback -f "udp port 5353"` while it runs, convert the result with `editcap -F pcap` and `editcap -F nsecpcap`, then compare `test_capture --read <files>` with tshark's count (`tshark -r <file> -Y udp.port==5353`). `tools\drive_capture.ps1 -Exe <exe> -File <capture> -Expect <tshark's count>` then drives the GUI through the same file, by the command line, the Open dialog and a drop.
- **Layout:** `tools\drive_layout.ps1 -Exe <exe> -File <capture>` drags each splitter and sends a DPI change, and checks what moved.
- **Power of 10:** `python tools/p10.py` measures the code against the rules; the results and the recorded deviations are in [docs/POWER_OF_10.md](docs/POWER_OF_10.md).
- A capture made on a real interface carries the LAN's host names and addresses: keep it in the git-ignored `build/claude-scratch/`, as the drivers' screenshots are.

## Layout

| Path | Contents |
|---|---|
| `src/core/Capture.*` | pcap and pcapng reader: link layers, IP, UDP, and the mDNS datagrams out of them |
| `src/core/Dns.*` | Wire-format decoder: produces the structured message, the decode tree and the log summary |
| `src/core/Conversations.*` | Per-source-host summary table (bounded: 4,096 hosts, 64 names per list) |
| `src/core/HexDump.*` | Hex dump text, and the byte-range to character-range mapping used for highlighting |
| `src/core/Listener.*` | Sockets, group membership and the receive thread; also the `Packet` both sources produce |
| `src/core/Sequence.*` | Sequence chart model: which messages relate, query/response matching, lifelines (capped at 16) |
| `src/gui/Main.cpp` | The window |
| `src/gui/SequenceView.*` | The chart window (GDI, double-buffered, scrolls both ways) |
| `src/gui/MdnsListener.rc`, `.manifest`, `version.h.in` | Version resource and icon, per-monitor DPI v2 and common controls v6, the generated version header |
| `src/gui/MdnsListener.ico` | The icon, generated by `tools/make_icon.py` (Pillow); regenerate it rather than edit it |
| `tests/test_mdns.cpp` | Decoder, hex-dump, conversation-table, sequence and 200,000-packet fuzz tests |
| `tests/test_capture.cpp` | Capture reader tests: both pcap byte orders and resolutions, multi-section multi-interface pcapng, every link type, fragments, snapped and damaged files, and a 100,000-file fuzz pass. `test_capture --read <files>` prints what the reader makes of real captures |
| `tools/feed_mdns.py` | Bench feeder: a two-host exchange over the **loopback interface only**: queries (and optionally malformed packets) from 127.0.0.1, responses from 127.0.0.2 |
| `tools/drive_smoke.ps1` | Live GUI driver: launches its own instance and feeds it. It checks the count one-for-one, selects a row, a tree line, the Sequence tab and a conversation, and checks that Pause holds and Resume releases every packet. It captures PNGs into `build/claude-scratch/` and closes the instance. `-Exe` picks the build |
| `tools/drive_capture.ps1` | Capture-file GUI driver. It opens `-File` from the command line, through the Open dialog, and by a drop, and checks the counts against `-Expect` and the log's rows. It decodes the first packet and checks that Start and Clear leave the file. It checks that a non-capture, given any of those three ways, raises exactly one warning and changes nothing |
| `tools/drive_layout.ps1` | Layout driver: drags each splitter by a known distance and past its limit, then sends `WM_DPICHANGED` to 96 dpi and back, and checks the panes, the window rectangle, the button heights and the column widths |
| `tools/p10.py` | Power of 10 measurements of `src/core` and `src/gui` (`mypy --strict` and `ruff` clean) |
| `tools/make_icon.py` | Draws each icon size on its own and writes the `.ico` |
| `docs/POWER_OF_10.md` | The Power of 10 pass: figures, rule by rule, and the deviations |

A dropped file's handle has to be made inside the app's own process, so a script cannot post one. The drop driver therefore sends the same `DROPFILES` block the shell would build, as a `WM_COPYDATA` tagged `MDND`. The app copies that block into a real handle and posts itself `WM_DROPFILES`, so the drop handler runs exactly as it does for Explorer. The one part not driven is Explorer building that handle. The DPI check is likewise sent rather than caused, because it was written on a single-monitor machine.

## Power of 10 deviations

The full pass is in [docs/POWER_OF_10.md](docs/POWER_OF_10.md). In short:

- The receive loop and the UI message pump are unbounded by design.
- `WSARecvMsg` can only be reached through an extension function pointer (`Listener::recvMsg_`), so the program has that one function pointer.
- The log, the conversation table, the held packets and a capture file's buffer live in standard containers on the heap. Each is capped (20,000 packets, 4,096 hosts, 1 GiB), but they grow after initialisation rather than being preallocated.
- Most functions outside the capture reader still carry fewer than two asserts. Input from the network or a file is validated and reported rather than asserted, so asserts belong only on internal invariants, and those have yet to be worked through file by file.
