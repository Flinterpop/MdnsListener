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
| 5 | At least two asserts per function | **Partly.** Real invariants were added across `Capture.cpp` (below). Bytes from the network or from a file are validated and *reported* (a decode fault, a status-line warning, a refusal message), never asserted. That is why the parsing functions carry fewer asserts than their size suggests. The remaining shortfall is listed under deviations. |
| 6 | Smallest scope | **Pass** on spot checks of `Capture.cpp`, `Listener.cpp` and `Main.cpp`. |
| 7 | Check return values | **Pass.** Every ignored result is now an explicit `(void)` with its reason: `closesocket` and `WSACleanup` on teardown paths, and `CloseHandle` on a read-only file. The two `bind` hits are inside an `if` (a false positive of the pattern). |
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

1. **Rule 5 outside `Capture.cpp`:** most of the core's functions have fewer than two asserts:
   - `Dns.cpp` 33
   - `Listener.cpp` 16
   - `Sequence.cpp` 12
   - `Conversations.cpp` 4
   - `Capture.cpp` 8, which are one-line byte readers (`Get16` and the like), `LinkPayload`'s switch, and `ReadCaptureFile`, whose input is a path it reports on.

   I chose not to pad these in this pass. Each needs reading for the invariants it actually has, and that work is its own pass.
2. **Rule 5 in the GUI:** 74 of 78 functions. They are mostly message handlers whose inputs Windows guarantees.
3. **Rule 3:** heap containers, each with a cap, as above.
4. **Rule 2:** the receive loop and the message pump.
5. **Rule 9:** the `WSARecvMsg` function pointer.
6. **Rule 4:** `WndProc` (69 lines, a dispatch table).
7. **The chart window's state** is a raw `new (std::nothrow)` / `delete` pair owned through `GWLP_USERDATA`. This is the usual Win32 idiom for per-window data, and it is now deleted at exactly one point.
