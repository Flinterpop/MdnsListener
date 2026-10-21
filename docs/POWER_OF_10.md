# Power of 10

*First pass: 20 Oct 2026, at v0.2.1.* Re-run `python tools/p10.py` when the core changes shape, and add a dated section at the bottom saying what moved.

The rules are G. Holzmann's *The Power of 10: Rules for Developing Safety-Critical Code* (NASA/JPL). MDNS Listener is a desktop tool, not flight software, so the pass measures the code against the rules, fixes the real violations, and records the rest below as deviations with their reasons.

## Scope and method

- **In scope: `src/core`** (`mdnscore`): the DNS decoder, the capture reader, the listener, the conversation table and the sequence model. This is the code that handles bytes from the network or from a file. This pass focused on `Capture.cpp`, which is new in v0.2.
- **Measured, out of scope:** `src/gui` (the window and the chart) and `tests`. Their figures are recorded so that the exclusion is a visible choice.
- **`tools/p10.py`** reads text, not an AST. A definition starts at column 0, in either brace style, and runs to the next `}` at column 0. Inline functions in headers are therefore not counted, and every hit was checked by hand.
- **Rule 10:** a separate MSVC `/analyze` build of everything (`/EHsc /analyze /analyze:WX- /analyze:external-`, Debug), on top of the normal `/W4 /WX /permissive-`.
- **Asserts compile away in Release**, so both suites were run in Debug as well. That includes `test_capture`'s 100,000-file fuzz pass and `test_mdns`'s 200,000-packet decoder fuzz. All three GUI drivers ran on Debug and Release.

## Measured

| | `src/core` | `src/gui` | `tests` |
|---|---|---|---|
| Non-blank lines | 2,154 | 1,685 | 750 |
| Functions | 95 | 78 | 33 |
| `assert(` in functions | 79 | 29 | 0 (they use `CHECK`) |
| Functions with fewer than two asserts | 73 (`Capture.cpp` 8 of 18) | 74 | — |
| Functions over 60 lines | 0 | 1 (`WndProc`, 69) | 0 |
| goto / setjmp / recursion | 0 | 0 | 0 |
| Raw `new` / `delete` | 0 | 1 pair (`SequenceView` window state) | 0 |
| Function pointers | 1 (`WSARecvMsg`) | 0 | 0 |
| `/analyze` findings | 0 | 2, both fixed (see below) | 0 |

## Rule by rule

| # | Rule | Result |
|---|---|---|
| 1 | No goto, setjmp or recursion | **Pass.** Compression pointers are followed iteratively, with a cap on steps per name. |
| 2 | Fixed loop bounds | **Pass, with one deviation.** Every loop over input data is bounded: frames and blocks per file, options per block, IPv6 extension headers, reads per file, and compression steps per name. The receive loop and the message pump run until told to stop, by design. |
| 3 | No heap after initialisation | **Deviation.** The log, the conversation table, held packets and a capture file's buffer are standard containers. Each is capped (20,000 packets, 4,096 hosts with 64 names a list, 1 GiB per file) but grows after start-up. |
| 4 | Functions of at most about 60 lines | **Pass in the core.** In the GUI, `WndProc` is 69 lines of one-line dispatch cases, which reads better as one table. |
| 5 | At least two asserts per function | **Pass in the core, with 21 recorded exceptions** (since the second pass, below). Bytes from the network or from a file are validated and *reported* (a decode fault, a status-line warning, a refusal message), never asserted. The asserts are on what the code itself guarantees: positions inside the packet or frame, caps on lists, the order calls are made in. |
| 6 | Smallest scope | **Pass** on spot checks of `Capture.cpp`, `Listener.cpp` and `Main.cpp`. |
| 7 | Check return values | **Pass** (since the second pass, which found four results the first pass missed: see below). Every ignored result is an explicit `(void)` with its reason: `closesocket` and `WSACleanup` on teardown paths, and `CloseHandle` on a read-only file. The two `bind` hits are inside an `if` (a false positive of the pattern). |
| 8 | Limit the preprocessor | **Pass.** The core has none beyond `#pragma once`. The tests' `CHECK` macro exists to report `__LINE__`. |
| 9 | One level of pointers, no function pointers | **Deviation.** `WSARecvMsg` can only be reached through the extension function pointer Winsock hands back (`Listener::recvMsg_`). `char** argv` appears in the tests. |
| 10 | All warnings, zero warnings | **Pass.** `/W4 /WX` is clean. `/analyze` found two problems, both now fixed. |

### What this pass changed

- **`/analyze` C6001, `SequenceView.cpp`:** after `WM_NCDESTROY` deleted the chart's state, the window procedure fell through to code that tested, and could have dereferenced, the freed pointer. It now returns straight to `DefWindowProcW`. It was harmless only because no later `case` handled that message.
- **`/analyze` C28251, `Main.cpp`:** `wWinMain` now carries the SDK's SAL annotations.
- **Rule 5, `Capture.cpp`:** 18 asserts were added and two widened, each on an invariant the code relies on:
  - the UDP offset and datagram end lie inside the captured bytes after `ParseIpv4`/`ParseIpv6`;
  - the link header was skipped only when it fit;
  - the payload copy stays inside the frame;
  - a pcapng option walk never passes the block by more than its padding;
  - `Resolution` never returns 0, since `NgTime` divides by it;
  - the packet list never exceeds its cap;
  - a refused file always says why.
- **A real defect found while reading:** if `ReadFile` failed part way through a capture, the reader treated the file as shorter than it is and said nothing. The status line now says "Only part of the file could be read."
- **Rule 7:** the six discarded results named above are now explicit.
- **The measuring script itself:** the shared `p10.py` counted 0 functions in this repo, because it only recognised `name(...) {` on a single line. It now handles a brace on its own line and multi-line signatures, and lists the functions that have fewer than two asserts.

## Remaining deviations (for the next pass to tick off)

1. **Rule 5, 21 core functions with fewer than two asserts.** Each has one real assert or none, and no second invariant worth stating:
   - **Byte readers:** `Get16`, `Get32`, `Get64` (`Capture.cpp`) and `ReadU16`, `ReadU32` (`Dns.cpp`). The callers check the length; the readers see only a pointer, or are themselves the bounds check.
   - **Name tables, total over their input:** `OpcodeName`, `RcodeName` (each asserts its four-bit range), `EdnsOptionName`, `SectionTitle`, `TypeName`, `ClassName`, `IsGroupAddress`, `Lower`.
   - **Thin wrappers:** `Narrow`, `Now`, `Listener::InterfaceName`, `Millis`.
   - **Covered by their callers or callees:** `RdataSrv` and `RdataMx` (the record lies in the packet; the name's own checks are in `RdataName`), `Intersects` and `Shares` (both lists capped; `InAny` checks the other side).
2. **Rule 5 in the GUI:** 74 of 78 functions. They are mostly message handlers whose inputs Windows guarantees.
3. **Rule 3:** heap containers, each with a cap, as above.
4. **Rule 2:** the receive loop and the message pump.
5. **Rule 9:** the `WSARecvMsg` function pointer.
6. **Rule 4:** `WndProc` (69 lines, a dispatch table).
7. **The chart window's state** is a raw `new (std::nothrow)` / `delete` pair owned through `GWLP_USERDATA`. This is the usual Win32 idiom for per-window data, and it is now deleted at exactly one point.

## Second pass: 20 Oct 2026, at v0.2.2: rule 5 across the rest of the core

The table above is the first pass. What moved in `src/core`:

| | First pass | Second pass |
|---|---|---|
| Non-blank lines | 2,154 | 2,262 |
| `assert(` in functions | 79 | 169 |
| Functions with fewer than two asserts | 73 of 95 | 21 of 95, each listed under deviations |
| Functions over 60 lines | 0 | 0 |
| `/analyze` findings | 0 | 0 |

**Rule 5, file by file.** The new asserts state what each function relies on, not a count:

- **`Dns.cpp`:**
  - every `Rdata*` function's record lies inside the packet;
  - `ReadName`'s end position is inside the packet and past its start;
  - `CharString` and the TXT, OPT, NSEC and SOA walks end exactly where their checks say;
  - TXT and OPT start from an empty result, which their separators assume;
  - `Fail` leaves an error behind, which `Decode`'s result depends on;
  - each section's index into `counts[4]` is in range;
  - questions and records advance the position and stay in the packet.
- **`Listener.cpp`:**
  - nothing touches the sockets or the adapter list while the receive thread runs;
  - a socket is never opened over one that is already open, which would leak it;
  - `WSARecvMsg` is loaded before the thread can call it;
  - the receive thread starts with at least one socket;
  - a source address is IPv4 or IPv6.
- **`Sequence.cpp` and `Conversations.cpp`:**
  - the name lists stay within their caps, which bound every search over them;
  - only responses are asked whether they are goodbyes or answers to a query;
  - a conversation table's two indexes agree.
- **`Capture.cpp`:** the VLAN walk stays in the frame, `Address` gets a real family, `Resolution`'s binary branch now goes through the same non-zero check as its decimal one, and `ReadCaptureFile` always explains a refusal.

**Rule 7: the first pass missed four results.** Its "Pass" was wrong:
- `inet_pton` was ignored twice, once for each multicast group in `Listener::OpenV4`/`OpenV6`. Each group is now parsed once, and the result is asserted and checked.
- `snprintf` was ignored in `WsaError` and `Millis`. Both now check it and fall back to a plain string.

**A real defect, found while reading: `NgTime` could overflow.** It added a file's `if_tsoffset`, an arbitrary 64-bit value, to the timestamp in signed arithmetic. An offset near `INT64_MAX` overflowed, which is undefined behaviour. In practice it wrapped to a negative time, which the reader reported as "no time". The offset is now clamped to the range a plausible time allows.
- `test_capture` has a new `TestTimeOffset` covering ±1 hour, both extremes, and an offset that moves the time before 1970.
- The ±1 hour cases are the first test of `if_tsoffset` at all.
- The extremes give the same answer before and after the fix, so the test cannot show the overflow itself. MSVC has no undefined-behaviour sanitiser, and the assert in `NgTime` is what now guards the sum.

**Verified:**
- `/W4 /WX` is clean in Debug and Release, and `/analyze` is clean.
- `test_mdns` (91 checks) and `test_capture` (132) pass in Debug, with every new assert live through both fuzz passes, and in Release.
- `drive_smoke`, `drive_layout` and `drive_capture` pass on Debug and Release. `drive_capture` was run on all four oracle captures in Debug, and on `two.pcapng` in Release.
